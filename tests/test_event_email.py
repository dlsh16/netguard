"""Use NETGUARD_TEST_DSN for a disposable PostgreSQL database (never production)."""
import asyncio
import os
from pathlib import Path
import socketserver
import sys
import threading
import unittest
from unittest.mock import AsyncMock, Mock, patch
from uuid import uuid4

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

import asyncpg
import app as application
import database
from alerts.alert_manager import AlertManager
from config import Settings
from email.mime.text import MIMEText
from event_utils import event_dedupe_key
from smtp_client import SMTPDeliveryUncertain, send_smtp_message


class EventIdentityTests(unittest.TestCase):
    def test_readings_change_but_ports_and_disks_stay_distinct(self):
        def key(text):
            return event_dedupe_key(1, "warning", "performance", text)
        self.assertEqual(key("CPU 81.5%"), key("CPU 84.2%"))
        self.assertEqual(key("Z-score: 3.2, delta 40.5%p"), key("Z-score: 4.8, delta 57.2%p"))
        self.assertNotEqual(key("port GigabitEthernet1/0/35 down"), key("port GigabitEthernet1/0/36 down"))
        self.assertNotEqual(key("disk /data1 85%"), key("disk /data2 85%"))


@unittest.skipUnless(os.getenv("NETGUARD_TEST_DSN"), "Set NETGUARD_TEST_DSN to run PostgreSQL checks")
class EventEmailTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.schema = "test_email_" + uuid4().hex
        self.admin = await asyncpg.connect(os.environ["NETGUARD_TEST_DSN"])
        await self.admin.execute(f'CREATE SCHEMA "{self.schema}"')
        self.pool = await asyncpg.create_pool(
            os.environ["NETGUARD_TEST_DSN"], min_size=1, max_size=12,
            server_settings={"search_path": self.schema},
        )
        async with self.pool.acquire() as conn:
            await database._init_db_locked(conn)
            await conn.execute("INSERT INTO devices (name, type, ip_address) VALUES ('server1', 'server', '192.0.2.1')")
            self.devices = [dict(r) for r in await conn.fetch("SELECT * FROM devices")]
        self.db_patch = patch("database.get_db_pool", AsyncMock(return_value=self.pool))
        self.db_patch.start()
        self.smtp_send = Mock()
        self.manager = self.new_manager()

    def new_manager(self):
        manager = AlertManager()
        manager.settings = Settings(SMTP_HOST="smtp.invalid", ALERT_EMAILS=["ops@example.invalid"])
        manager._refresh_global_thresholds = AsyncMock()
        manager._smtp_send = self.smtp_send
        manager._send_kakao = AsyncMock()
        return manager

    async def asyncTearDown(self):
        self.db_patch.stop()
        await self.pool.close()
        await self.admin.execute(f'DROP SCHEMA "{self.schema}" CASCADE')
        await self.admin.close()

    async def cycle(self, value=81.0, manager=None):
        manager = manager or self.manager
        alerts = await manager.evaluate({"device": "server1", "type": "server", "metrics": {"cpu_pct": value}})
        saved = await application._save_events(self.pool, self.devices, alerts)
        for alert in saved:
            await manager.dispatch(alert)
        return saved

    async def test_evaluation_does_not_send_before_event_saved(self):
        alerts = await self.manager.evaluate({"device": "server1", "metrics": {"cpu_pct": 81}})
        self.assertEqual(len(alerts), 1)
        self.smtp_send.assert_not_called()
        await self.manager.dispatch(alerts[0])
        self.smtp_send.assert_not_called()

    async def test_reading_changes_acknowledgement_and_restart_send_once(self):
        saved = await self.cycle()
        await self.pool.execute("UPDATE events SET status='acknowledged', time=NOW()-INTERVAL '2 days'")
        for value in (82, 84, 81, 83):
            self.assertEqual(await self.cycle(value, self.new_manager()), [])
        await self.new_manager().dispatch(saved[0])
        self.smtp_send.assert_called_once()
        self.assertEqual(await self.pool.fetchval("SELECT count(*) FROM events"), 1)
        self.assertEqual(await self.pool.fetchval("SELECT status FROM notification_log"), "sent")

    async def test_resolved_event_can_notify_on_recurrence(self):
        first = (await self.cycle())[0]
        await self.pool.execute("UPDATE events SET status='resolved' WHERE id=$1", first["id"])
        second = (await self.cycle())[0]
        self.assertNotEqual(first["id"], second["id"])
        self.assertEqual(self.smtp_send.call_count, 2)

    async def test_legacy_unresolved_event_is_not_resent_on_upgrade(self):
        alerts = await self.manager.evaluate({"device": "server1", "metrics": {"cpu_pct": 81}})
        await application._save_events(self.pool, self.devices, alerts)
        self.assertEqual(await self.cycle(82, self.new_manager()), [])
        self.smtp_send.assert_not_called()

    async def test_concurrent_collectors_and_dispatchers_send_once(self):
        alerts = await self.manager.evaluate({"device": "server1", "metrics": {"cpu_pct": 81}})
        batches = await asyncio.gather(*(
            application._save_events(self.pool, self.devices, alerts) for _ in range(10)
        ))
        saved = [alert for batch in batches for alert in batch]
        self.assertEqual(len(saved), 1)
        await asyncio.gather(*(self.new_manager().dispatch(saved[0]) for _ in range(10)))
        self.smtp_send.assert_called_once()
        self.assertEqual(await self.pool.fetchval("SELECT count(*) FROM notification_log"), 1)

    async def test_failed_or_uncertain_delivery_is_not_retried(self):
        for exception, state in ((OSError("connection refused"), "failed"), (SMTPDeliveryUncertain("lost DATA response"), "unknown")):
            self.smtp_send.side_effect = exception
            saved = (await self.cycle())[0]
            calls = self.smtp_send.call_count
            await self.new_manager().dispatch(saved)
            self.assertEqual(self.smtp_send.call_count, calls)
            self.assertEqual(await self.pool.fetchval("SELECT status FROM notification_log WHERE event_id=$1", saved["id"]), state)
            await self.pool.execute("UPDATE events SET status='resolved' WHERE id=$1", saved["id"])

    async def test_inflight_claim_survives_restart(self):
        saved = (await self.cycle())[0]
        await self.pool.execute("UPDATE notification_log SET status='sending'")
        await self.new_manager().dispatch(saved)
        self.smtp_send.assert_called_once()

    async def test_database_failure_does_not_send_untracked_mail(self):
        alerts = await self.manager.evaluate({"device": "server1", "metrics": {"cpu_pct": 81}})
        with patch("app.save_event_once", AsyncMock(side_effect=OSError("database unavailable"))):
            self.assertEqual(await application._save_events(self.pool, self.devices, alerts), [])
        self.smtp_send.assert_not_called()

    async def test_level_filter_and_unconfigured_smtp_do_not_send(self):
        self.manager.settings.ALERT_NOTIFY_HIGH = False
        saved = (await self.cycle())[0]
        self.smtp_send.assert_not_called()
        self.manager.settings.ALERT_NOTIFY_HIGH = True
        self.manager.settings.ALERT_EMAILS = []
        await self.manager.dispatch(saved)
        self.smtp_send.assert_not_called()
        self.assertEqual(await self.pool.fetchval("SELECT count(*) FROM notification_log"), 0)

    async def test_delete_event_keeps_delivery_audit_and_migration_is_repeatable(self):
        saved = (await self.cycle())[0]
        async with self.pool.acquire() as conn:
            # Simulate the previous schema, then apply the real startup migration twice.
            await conn.execute("""ALTER TABLE notification_log
                ALTER COLUMN recipient TYPE VARCHAR(200),
                DROP CONSTRAINT notification_log_event_id_fkey,
                ADD CONSTRAINT notification_log_event_id_fkey FOREIGN KEY (event_id) REFERENCES events(id)""")
            await database._init_db_locked(conn)
            await database._init_db_locked(conn)
            self.assertEqual(await conn.fetchval("SELECT count(*) FROM devices"), 1)
            self.assertEqual(await conn.fetchval("SELECT count(*) FROM users"), 1)
            await conn.execute("DELETE FROM events WHERE id=$1", saved["id"])
            row = await conn.fetchrow("SELECT event_id, status FROM notification_log")
            self.assertIsNone(row["event_id"])
            self.assertEqual(row["status"], "sent")


class SMTPDeliveryTests(unittest.TestCase):
    def run_relay(self, data_reply):
        commands = []

        class Relay(socketserver.StreamRequestHandler):
            def handle(self):
                self.request.settimeout(3)
                self.wfile.write(b"220 test relay\r\n")
                while True:
                    line = self.rfile.readline()
                    if not line:
                        return
                    commands.append(line.split(b" ")[0].strip())
                    if line.startswith(b"EHLO"):
                        self.wfile.write(b"250-test relay\r\n250 SMTPUTF8\r\n")
                    elif line.startswith((b"MAIL", b"RCPT")):
                        self.wfile.write(b"250 OK\r\n")
                    elif line == b"DATA\r\n":
                        self.wfile.write(b"354 send body\r\n")
                        while self.rfile.readline() != b".\r\n":
                            pass
                        if data_reply is None:
                            return
                        self.wfile.write(data_reply)
                    elif line == b"QUIT\r\n":
                        return  # Simulate connection loss after acceptance.

        with socketserver.TCPServer(("127.0.0.1", 0), Relay) as server:
            thread = threading.Thread(target=server.handle_request, daemon=True)
            server.timeout = 3
            thread.start()
            settings = Settings(SMTP_HOST="127.0.0.1", SMTP_PORT=server.server_address[1], SMTP_TIMEOUT=2)
            try:
                with patch("smtp_client.smtplib.SMTP", side_effect=AssertionError("Must not resend via fallback")):
                    send_smtp_message(settings, MIMEText("one message"), ["ops@example.invalid"])
            finally:
                thread.join(timeout=4)
                self.assertFalse(thread.is_alive())
                self.assertEqual(commands.count(b"DATA"), 1)

    def test_accepted_message_is_not_resent_when_quit_disconnects(self):
        self.run_relay(b"250 accepted\r\n")

    def test_lost_data_reply_is_uncertain_and_not_resent(self):
        with self.assertRaises(SMTPDeliveryUncertain):
            self.run_relay(None)


if __name__ == "__main__":
    unittest.main()
