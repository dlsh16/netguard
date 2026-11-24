"""Identity migrations and API regression checks in a disposable loopback DB."""
import asyncio
from datetime import datetime, timezone
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import AsyncMock, patch
from urllib.parse import urlparse
from uuid import uuid4

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'backend'))
import asyncpg
import httpx
from fastapi import FastAPI
from agent_identity import init_agent_identity_schema
from api import agent_routes
from software_inventory import init_inventory_schema


@unittest.skipUnless(os.getenv('NETGUARD_SOFTWARE_TEST_DSN'), 'Disposable PostgreSQL DSN not set')
class IdentityApiTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        dsn = os.environ['NETGUARD_SOFTWARE_TEST_DSN']
        if urlparse(dsn).hostname not in ('localhost', '127.0.0.1'):
            raise RuntimeError('Only a disposable loopback database is allowed')
        self.schema = 'test_agent_identity_' + uuid4().hex
        self.admin = await asyncpg.connect(dsn)
        await self.admin.execute('CREATE SCHEMA ' + self.schema)
        self.pool = await asyncpg.create_pool(dsn, min_size=1, max_size=5, server_settings={'search_path': self.schema})
        async with self.pool.acquire() as conn:
            await conn.execute('''CREATE TABLE devices(id SERIAL PRIMARY KEY, name VARCHAR(100) UNIQUE NOT NULL,
                ip_address INET NOT NULL, type TEXT NOT NULL, snmp_version TEXT, os_version TEXT,
                location TEXT, enabled BOOLEAN DEFAULT TRUE, updated_at TIMESTAMPTZ DEFAULT NOW());
                CREATE TABLE metrics(time TIMESTAMPTZ,device_id INTEGER REFERENCES devices(id),metric_name TEXT,value DOUBLE PRECISION);
                CREATE TABLE thresholds(device_id INTEGER,metric_name TEXT,warn_value DOUBLE PRECISION,crit_value DOUBLE PRECISION);
                CREATE TABLE users(id SERIAL PRIMARY KEY,name TEXT);
                INSERT INTO users(name) VALUES('preserved-admin');''')
            await init_agent_identity_schema(conn)
            await init_agent_identity_schema(conn)
            await init_inventory_schema(conn)
        self.patch = patch.object(agent_routes, 'get_db_pool', AsyncMock(return_value=self.pool))
        self.patch.start()
        app = FastAPI(); app.include_router(agent_routes.router)
        self.client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://test',
                                        headers={'X-Agent-Key': agent_routes.AGENT_API_KEY})
        agent_routes.AGENT_LIVE_RESULTS.clear()

    async def asyncTearDown(self):
        await self.client.aclose()
        self.patch.stop()
        agent_routes.AGENT_LIVE_RESULTS.clear()
        await self.pool.close()
        await self.admin.execute('DROP SCHEMA ' + self.schema + ' CASCADE')
        await self.admin.close()

    async def register(self, name='server', ip='192.0.2.1', identity='a' * 64):
        payload = dict(hostname=name, ip_address=ip, os='Linux fixture', location='rack A')
        if identity is not None:
            payload['agent_id'] = identity
        return await self.client.post('/api/agent/register', json=payload)

    async def metrics(self, ip='192.0.2.1', identity='a' * 64):
        return await self.client.post('/api/agent/metrics', json=dict(hostname='server', ip_address=ip, agent_id=identity, cpu_pct=3))

    async def inventory(self, ip='192.0.2.1', identity='a' * 64):
        return await self.client.post('/api/agent/software', json=dict(hostname='server', ip_address=ip, agent_id=identity,
            collected_at=datetime.now(timezone.utc).isoformat(), items=[dict(name='PHP',version='8.2.1',source='rpm')]))

    async def test_ip_change_preserves_device_history_inventory_and_cache(self):
        first = await self.register()
        self.assertEqual(first.status_code, 200, first.text)
        device = first.json()['device_id']
        self.assertEqual((await self.metrics()).status_code, 200)
        self.assertEqual((await self.inventory()).status_code, 200)
        changed = await self.metrics('192.0.2.130')
        self.assertEqual(changed.json()['device_id'], device)
        self.assertEqual((await self.inventory('192.0.2.130')).status_code, 200)
        self.assertEqual(list(agent_routes.AGENT_LIVE_RESULTS), ['192.0.2.130'])
        self.assertEqual(await self.pool.fetchval('SELECT count(*) FROM devices'), 1)
        self.assertEqual(await self.pool.fetchval('SELECT count(*) FROM metrics WHERE device_id=$1', device), 10)
        self.assertEqual(await self.pool.fetchval('SELECT count(*) FROM software_inventory WHERE device_id=$1', device), 1)
        self.assertEqual(await self.pool.fetchval('SELECT os_version FROM devices'), 'Linux fixture')
        self.assertEqual(await self.pool.fetchval('SELECT name FROM users'), 'preserved-admin')
        self.assertEqual((await self.inventory()).status_code, 409)

    async def test_adopts_legacy_by_exact_ip_but_never_by_name_only(self):
        old = await self.register(identity=None)
        updated = await self.register()
        self.assertEqual(old.json()['device_id'], updated.json()['device_id'])
        for identity in ('b' * 64, None):
            conflict = await self.register(ip='192.0.2.2', identity=identity)
            self.assertEqual(conflict.status_code, 409, conflict.text)
        self.assertEqual(await self.pool.fetchval('SELECT count(*) FROM devices'), 1)

    async def test_different_device_ip_collision_does_not_merge(self):
        await self.register()
        second = await self.register(name='other', ip='192.0.2.2', identity='b' * 64)
        self.assertEqual(second.status_code, 200)
        conflict = await self.register(ip='192.0.2.2')
        self.assertEqual(conflict.status_code, 409)
        self.assertEqual(str(await self.pool.fetchval("SELECT ip_address FROM devices WHERE agent_id=$1", 'a' * 64)), '192.0.2.1')
        self.assertEqual((await self.register(identity='b' * 64)).status_code, 409)
        self.assertEqual(await self.pool.fetchval('SELECT count(*) FROM devices'), 2)

    async def test_simultaneous_registrations_produce_one_device(self):
        responses = await asyncio.gather(*(self.register() for _ in range(10)))
        self.assertTrue(all(r.status_code == 200 for r in responses), [r.text for r in responses])
        self.assertEqual(len({r.json()['device_id'] for r in responses}), 1)
        self.assertEqual(await self.pool.fetchval('SELECT count(*) FROM devices'), 1)

    async def test_existing_duplicates_and_non_server_are_rejected(self):
        await self.pool.execute("INSERT INTO devices(name,type,ip_address) VALUES('a','server','192.0.2.1'),('b','server','192.0.2.1'),('switch','switch','192.0.2.2')")
        self.assertEqual((await self.register()).status_code, 409)
        self.assertEqual((await self.register(ip='192.0.2.2')).status_code, 409)
        self.assertEqual(await self.pool.fetchval('SELECT count(*) FROM devices'), 3)

    async def test_old_other_ip_record_is_preserved_not_silently_deleted(self):
        await self.pool.execute("INSERT INTO devices(name,type,ip_address) VALUES('server','server','192.0.2.130'),('server (192.0.2.187)','server','192.0.2.187')")
        result = await self.register(ip='192.0.2.130')
        self.assertEqual(result.status_code, 200, result.text)
        self.assertEqual(result.json()['device_id'], 1)
        self.assertEqual(await self.pool.fetchval('SELECT count(*) FROM devices'), 2)
        self.assertIsNone(await self.pool.fetchval('SELECT agent_id FROM devices WHERE id=2'))
        self.assertEqual((await self.metrics('192.0.2.187')).status_code, 409)

    async def test_input_validation_auth_and_legacy_compatibility(self):
        self.assertEqual((await self.register(identity='invalid')).status_code, 422)
        self.assertEqual((await self.register(ip='bad-ip')).status_code, 422)
        denied = await self.client.post('/api/agent/register', json=dict(hostname='server',ip_address='192.0.2.1'), headers={'X-Agent-Key':'wrong'})
        self.assertEqual(denied.status_code, 403)
        legacy = await self.register(identity=None)
        changed = await self.register(ip='192.0.2.2', identity=None)
        self.assertEqual(legacy.json()['device_id'], changed.json()['device_id'])
        self.assertEqual((await self.inventory(ip='192.0.2.2', identity=None)).status_code, 200)


if __name__ == '__main__':
    unittest.main()
