"""
Alert Manager - evaluates metrics against thresholds and triggers notifications.
Supports email and KakaoTalk delivery when configured.
"""
import asyncio
import logging
import socket
import smtplib
import statistics
from collections import defaultdict, deque
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Deque, Dict, List, Optional

import aiohttp

logger = logging.getLogger("netguard.alerts")


def describe_smtp_error(exc: Exception, host: str, port: int) -> str:
    if isinstance(exc, socket.gaierror):
        return (
            f"SMTP host name resolution failed: {host}. "
            "Check DNS, /etc/hosts, or enter the SMTP server IP address directly."
        )
    if isinstance(exc, (ConnectionRefusedError, TimeoutError, socket.timeout)):
        return (
            f"SMTP server connection failed: {host}:{port}. "
            "Check firewall, routing, SMTP port, and relay service status."
        )
    if isinstance(exc, smtplib.SMTPServerDisconnected):
        return (
            f"SMTP server disconnected or did not send a valid SMTP response: {host}:{port}. "
            f"Stage/detail: {exc}. "
            "Check the SMTP port, TLS/STARTTLS mode, relay policy, and whether the server allows this NetGuard host."
        )
    if isinstance(exc, smtplib.SMTPAuthenticationError):
        return "SMTP authentication failed. Check SMTP account and password."
    if isinstance(exc, smtplib.SMTPRecipientsRefused):
        return "SMTP recipient was refused. Check the recipient address or relay policy."
    if isinstance(exc, smtplib.SMTPSenderRefused):
        return "SMTP sender was refused. Check the sender address or relay policy."
    if isinstance(exc, smtplib.SMTPException):
        return f"SMTP protocol error: {exc}"
    return f"SMTP send failed: {exc}"


def smtp_docmd(smtp: smtplib.SMTP, stage: str, command: str, args: Optional[str] = None):
    try:
        if args is None:
            return smtp.docmd(command)
        return smtp.docmd(command, args)
    except smtplib.SMTPServerDisconnected as e:
        raise smtplib.SMTPServerDisconnected(f"{stage}: {e}") from e
    except TimeoutError as e:
        raise smtplib.SMTPServerDisconnected(f"{stage}: timed out") from e


def smtp_ehlo_upper(smtp: smtplib.SMTP, hostname: str = "netguard-srv"):
    logger.info("SMTP stage: EHLO %s", hostname)
    code, msg = smtp_docmd(smtp, "EHLO", "EHLO", hostname)
    smtp.ehlo_resp = msg
    if code != 250:
        logger.info("SMTP stage: HELO %s", hostname)
        code, msg = smtp_docmd(smtp, "HELO", "HELO", hostname)
        smtp.helo_resp = msg
        if code != 250:
            raise smtplib.SMTPHeloError(code, msg)
        return code, msg

    smtp.does_esmtp = True
    smtp.esmtp_features = {}
    text = msg.decode("latin-1", errors="replace") if isinstance(msg, bytes) else str(msg)
    for line in text.splitlines():
        parts = line.strip().split()
        if not parts:
            continue
        feature = parts[0].lower()
        params = " ".join(parts[1:])
        smtp.esmtp_features[feature] = params
    return code, msg


def smtp_send_message_upper(smtp: smtplib.SMTP, msg: MIMEMultipart, sender: str, recipients: List[str]):
    logger.info("SMTP stage: MAIL FROM <%s>", sender)
    code, reply = smtp_docmd(smtp, "MAIL FROM", "MAIL", f"FROM:<{sender}>")
    if code != 250:
        raise smtplib.SMTPSenderRefused(code, reply, sender)

    refused = {}
    accepted = []
    for recipient in recipients:
        logger.info("SMTP stage: RCPT TO <%s>", recipient)
        code, reply = smtp_docmd(smtp, f"RCPT TO {recipient}", "RCPT", f"TO:<{recipient}>")
        if code in (250, 251):
            accepted.append(recipient)
        else:
            refused[recipient] = (code, reply)

    if not accepted:
        raise smtplib.SMTPRecipientsRefused(refused)

    logger.info("SMTP stage: DATA")
    code, reply = smtp_docmd(smtp, "DATA", "DATA")
    if code != 354:
        raise smtplib.SMTPDataError(code, reply)

    payload = msg.as_bytes()
    payload = payload.replace(b"\r\n", b"\n").replace(b"\r", b"\n").replace(b"\n", b"\r\n")
    lines = payload.split(b"\r\n")
    payload = b"\r\n".join((b"." + line if line.startswith(b".") else line) for line in lines)
    if not payload.endswith(b"\r\n"):
        payload += b"\r\n"
    smtp.send(payload + b".\r\n")

    code, reply = smtp.getreply()
    if code != 250:
        raise smtplib.SMTPDataError(code, reply)


class AlertManager:
    def __init__(self):
        from config import settings
        self.settings = settings
        self._history: Dict[str, Deque[float]] = defaultdict(lambda: deque(maxlen=60))
        self._active_alerts: Dict[str, dict] = {}
        self._switch_port_status: Dict[str, str] = {}
        self._thresholds_loaded_at: Optional[datetime] = None

    async def evaluate(self, device_data: dict) -> List[dict]:
        alerts = []
        name = device_data.get("device", "unknown")
        dev_type = device_data.get("type", "server")
        metrics = device_data.get("metrics", {})
        await self._refresh_global_thresholds()

        if device_data.get("status") == "offline":
            alerts.append(self._build_alert(
                name, "critical", "장비 오프라인", f"{name} SNMP 응답 없음 (오프라인)"
            ))
        elif dev_type == "server":
            alerts.extend(self._check_server(name, metrics))
        elif dev_type == "switch":
            alerts.extend(self._check_switch(name, metrics))
        elif dev_type == "ups":
            alerts.extend(self._check_ups(name, metrics))
        elif dev_type in ("env", "rpi", "environment", "sensor"):
            alerts.extend(self._check_env(name, metrics))

        for alert in alerts:
            await self._dispatch(alert)

        return alerts

    async def _refresh_global_thresholds(self):
        if (
            self._thresholds_loaded_at
            and datetime.now() - self._thresholds_loaded_at < timedelta(seconds=30)
        ):
            return

        metric_to_attrs = {
            "cpu_pct": ("CPU_WARN", "CPU_CRIT"),
            "mem_pct": ("MEM_WARN", "MEM_CRIT"),
            "disk_max_pct": ("DISK_WARN", "DISK_CRIT"),
            "temp_c": ("TEMP_WARN", "TEMP_CRIT"),
            "humidity_pct": ("HUMI_WARN_HIGH", None),
            "battery_pct": ("UPS_BATT_WARN", "UPS_BATT_CRIT"),
        }

        try:
            from database import get_db_pool
            pool = await get_db_pool()
            async with pool.acquire() as conn:
                rows = await conn.fetch("""
                    SELECT metric_name, warn_value, crit_value
                    FROM thresholds
                    WHERE device_id IS NULL
                """)
            for row in rows:
                attrs = metric_to_attrs.get(row["metric_name"])
                if not attrs:
                    continue
                warn_attr, crit_attr = attrs
                if row["warn_value"] is not None:
                    setattr(self.settings, warn_attr, row["warn_value"])
                if crit_attr and row["crit_value"] is not None:
                    setattr(self.settings, crit_attr, row["crit_value"])
        except Exception as e:
            logger.warning("Global threshold refresh failed; using current values: %s", e)
        finally:
            self._thresholds_loaded_at = datetime.now()

    def _check_server(self, name: str, metrics: dict) -> List[dict]:
        alerts = []
        s = self.settings

        cpu = metrics.get("cpu_pct", 0)
        self._history[f"{name}.cpu"].append(cpu)
        if cpu >= s.CPU_CRIT:
            alerts.append(self._build_alert(
                name, "critical", "성능", f"CPU 사용률 {cpu:.1f}% (위험: {s.CPU_CRIT}%)"
            ))
        elif cpu >= s.CPU_WARN:
            alerts.append(self._build_alert(
                name, "warning", "성능", f"CPU 사용률 {cpu:.1f}% (경고: {s.CPU_WARN}%)"
            ))

        hist = list(self._history[f"{name}.cpu"])
        if len(hist) >= 10:
            mean = statistics.mean(hist[:-1])
            stdev = statistics.stdev(hist[:-1]) or 1
            z = abs(cpu - mean) / stdev
            if z >= s.ANOMALY_ZSCORE_THRESHOLD and cpu > mean:
                alerts.append(self._build_alert(
                    name,
                    "warning",
                    "이상탐지",
                    f"CPU 이상 급증 탐지 (Z-score: {z:.1f}, 평균 대비 {cpu-mean:.1f}%p 초과)",
                ))

        mem = metrics.get("mem_pct", 0)
        if mem >= s.MEM_CRIT:
            alerts.append(self._build_alert(
                name, "critical", "성능", f"메모리 사용률 {mem:.1f}% (위험: {s.MEM_CRIT}%)"
            ))
        elif mem >= s.MEM_WARN:
            alerts.append(self._build_alert(
                name, "warning", "성능", f"메모리 사용률 {mem:.1f}% (경고: {s.MEM_WARN}%)"
            ))

        for disk in metrics.get("disks", []):
            pct = disk.get("used_pct", 0)
            path = disk.get("path", "?")
            if pct >= s.DISK_CRIT:
                alerts.append(self._build_alert(
                    name, "critical", "스토리지", f"디스크 {path} 사용률 {pct:.1f}% (위험: {s.DISK_CRIT}%)"
                ))
            elif pct >= s.DISK_WARN:
                alerts.append(self._build_alert(
                    name, "warning", "스토리지", f"디스크 {path} 사용률 {pct:.1f}% (경고: {s.DISK_WARN}%)"
                ))

        return alerts

    def _check_switch(self, name: str, metrics: dict) -> List[dict]:
        alerts = []
        for iface in metrics.get("interfaces", []):
            status = iface.get("status")
            port_id = iface.get("index", iface.get("name", "unknown"))
            state_key = f"{name}.{port_id}"
            previous_status = self._switch_port_status.get(state_key)
            if previous_status == "up" and status == "down":
                alerts.append(self._build_alert(
                    name, "critical", "네트워크", f"포트 {iface['name']} 다운 감지"
                ))
            if status in ("up", "down"):
                self._switch_port_status[state_key] = status
        return alerts

    def _check_ups(self, name: str, metrics: dict) -> List[dict]:
        alerts = []
        s = self.settings
        batt = metrics.get("battery_pct", 100)
        if batt <= s.UPS_BATT_CRIT:
            alerts.append(self._build_alert(
                name, "critical", "UPS", f"UPS 배터리 위험 {batt:.0f}% (위험: {s.UPS_BATT_CRIT}%)"
            ))
        elif batt <= s.UPS_BATT_WARN:
            alerts.append(self._build_alert(
                name, "warning", "UPS", f"UPS 배터리 경고 {batt:.0f}% (경고: {s.UPS_BATT_WARN}%)"
            ))
        return alerts

    def _check_env(self, name: str, metrics: dict) -> List[dict]:
        alerts = []
        s = self.settings
        temp = metrics.get("temp_c")
        if temp is not None:
            if temp >= s.TEMP_CRIT:
                alerts.append(self._build_alert(
                    name, "critical", "환경", f"전산실 온도 위험 {temp:.1f}°C (위험: {s.TEMP_CRIT}°C)"
                ))
            elif temp >= s.TEMP_WARN:
                alerts.append(self._build_alert(
                    name, "warning", "환경", f"전산실 온도 경고 {temp:.1f}°C (경고: {s.TEMP_WARN}°C)"
                ))
        humi = metrics.get("humidity_pct")
        if humi is not None and humi > s.HUMI_WARN_HIGH:
            alerts.append(self._build_alert(
                name, "warning", "환경", f"전산실 습도 높음 {humi:.0f}% (경고: {s.HUMI_WARN_HIGH}%)"
            ))
        return alerts

    @staticmethod
    def _build_alert(device: str, severity: str, category: str, message: str) -> dict:
        return {
            "device": device,
            "severity": severity,
            "category": category,
            "message": message,
            "timestamp": datetime.now().isoformat(),
        }

    async def _dispatch(self, alert: dict):
        key = f"{alert['device']}.{alert['category']}.{alert['message'][:30]}"
        existing = self._active_alerts.get(key)
        now = datetime.now()

        if existing:
            delta = (now - datetime.fromisoformat(existing["timestamp"])).seconds
            if delta < 600:
                return

        self._active_alerts[key] = alert
        logger.warning("ALERT [%s] %s: %s", alert["severity"].upper(), alert["device"], alert["message"])

        if alert["severity"] in ("critical", "warning"):
            await asyncio.gather(
                self._send_email(alert),
                self._send_kakao(alert),
                return_exceptions=True,
            )

    async def _send_email(self, alert: dict):
        s = self.settings
        if not s.ALERT_EMAILS or not s.SMTP_HOST:
            return
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"[NetGuard {alert['severity'].upper()}] {alert['device']}: {alert['message']}"
            msg["From"] = s.SMTP_FROM
            msg["To"] = ", ".join(s.ALERT_EMAILS)

            html = f"""
<html><body style="font-family:sans-serif;background:#0d1117;color:#e6edf3;padding:20px">
<h2 style="color:{'#ef4444' if alert['severity']=='critical' else '#f59e0b'}">
  [{alert['severity'].upper()}] {alert['device']}
</h2>
<p><strong>메시지:</strong> {alert['message']}</p>
<p><strong>카테고리:</strong> {alert['category']}</p>
<p><strong>발생시간:</strong> {alert['timestamp']}</p>
<hr/>
<p style="color:#8b949e;font-size:12px">NetGuard SNMP 모니터링 시스템</p>
</body></html>"""
            msg.attach(MIMEText(html, "html", "utf-8"))

            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, self._smtp_send, msg, s)
        except Exception as e:
            logger.error("Email send failed: %s", describe_smtp_error(e, s.SMTP_HOST, s.SMTP_PORT))

    @staticmethod
    def _smtp_send(msg, s):
        timeout = int(getattr(s, "SMTP_TIMEOUT", 30) or 30)
        smtp_cls = smtplib.SMTP_SSL if int(s.SMTP_PORT) == 465 else smtplib.SMTP
        smtp = smtp_cls(s.SMTP_HOST, s.SMTP_PORT, timeout=timeout)
        try:
            smtp_ehlo_upper(smtp)
            if int(s.SMTP_PORT) != 465 and getattr(s, "SMTP_STARTTLS", False):
                smtp.starttls()
                smtp_ehlo_upper(smtp)
            if s.SMTP_USER:
                if int(s.SMTP_PORT) != 465:
                    if not getattr(s, "SMTP_STARTTLS", False):
                        smtp.starttls()
                        smtp_ehlo_upper(smtp)
                smtp.login(s.SMTP_USER, s.SMTP_PASSWORD)
            smtp_send_message_upper(smtp, msg, s.SMTP_FROM, s.ALERT_EMAILS)
        finally:
            try:
                smtp.docmd("QUIT")
            except Exception:
                smtp.close()

    async def _send_kakao(self, alert: dict):
        s = self.settings
        if not s.KAKAO_ENABLED or not s.KAKAO_REST_KEY:
            return
        try:
            prefix = "[긴급]" if alert["severity"] == "critical" else "[경고]"
            text = (
                f"{prefix} [{alert['severity'].upper()}] {alert['device']}\n"
                f"메시지: {alert['message']}\n"
                f"발생시간: {alert['timestamp']}\n"
                "NetGuard 모니터링"
            )
            async with aiohttp.ClientSession() as session:
                await session.post(
                    "https://kapi.kakao.com/v2/api/talk/memo/default/send",
                    headers={"Authorization": f"Bearer {s.KAKAO_REST_KEY}"},
                    data={"template_object": f'{{"object_type":"text","text":"{text}","link":{{}}}}'},
                )
        except Exception as e:
            logger.error("Kakao send failed: %s", e)
