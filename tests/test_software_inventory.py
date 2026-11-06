"""Set NETGUARD_SOFTWARE_TEST_DSN to a disposable loopback PostgreSQL database."""
import asyncio
import json
import os
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import AsyncMock, patch
from urllib.parse import urlparse
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'backend'))
import asyncpg
import httpx
import app as application
from api import software_routes, agent_routes
from auth.jwt_handler import create_token
from software_inventory import SoftwareReport, SoftwareFilter, init_inventory_schema, save_inventory, search_inventory, inventory_coverage, inventory_csv, parse_filters, search_where
from software_fixtures import seed


class InventoryUnitTests(unittest.TestCase):
    def test_filters_are_parameterized(self):
        attack = "x' OR TRUE --"
        sql, args = search_where([SoftwareFilter(field='software_name', value=attack)])
        self.assertNotIn(attack, sql)
        self.assertEqual(args, [attack.lower()])
        self.assertRaises(ValueError, parse_filters, '{}')
        self.assertRaises(ValueError, parse_filters, '[{"field":"password","value":"test"}]')
        self.assertRaises(ValueError, parse_filters, json.dumps([{'field': 'server_name', 'value': 'x'}] * 21))

    def test_csv_excel_and_unicode(self):
        result = inventory_csv([{'server_name': '=HYPERLINK("x")', 'ip_address': '192.0.2.1', 'software_name': '한글,제품', 'software_version': '1.2'}])
        self.assertTrue(result.startswith('\ufeff'))
        self.assertIn("'=HYPERLINK", result)
        self.assertIn('"한글,제품"', result)

    def test_report_bounds_and_aware_time(self):
        for value in (datetime.now(), datetime.now(timezone.utc) + timedelta(days=1)):
            self.assertRaises(ValueError, SoftwareReport, hostname='test', ip_address='192.0.2.1', collected_at=value)
        self.assertRaises(ValueError, SoftwareFilter, field='software_name', value=' ')


@unittest.skipUnless(os.getenv('NETGUARD_SOFTWARE_TEST_DSN'), 'Disposable PostgreSQL DSN not set')
class InventoryDatabaseTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        dsn = os.environ['NETGUARD_SOFTWARE_TEST_DSN']
        if urlparse(dsn).hostname not in ('127.0.0.1', 'localhost'):
            raise RuntimeError('Software tests require a disposable loopback database')
        self.schema = 'test_software_' + uuid4().hex
        self.admin = await asyncpg.connect(dsn)
        await self.admin.execute('CREATE SCHEMA ' + self.schema)
        self.pool = await asyncpg.create_pool(dsn, min_size=1, max_size=4, server_settings={'search_path': self.schema})
        async with self.pool.acquire() as conn:
            await seed(conn)
        self.patch1 = patch.object(software_routes, 'get_db_pool', AsyncMock(return_value=self.pool))
        self.patch2 = patch.object(agent_routes, 'get_db_pool', AsyncMock(return_value=self.pool))
        self.patch1.start(); self.patch2.start()
        self.client = httpx.AsyncClient(transport=httpx.ASGITransport(app=application.app), base_url='http://test')
        self.headers = {'Authorization': 'Bearer ' + create_token({'username': 'operator', 'role': 'operator'}, application.settings.JWT_SECRET)}

    async def asyncTearDown(self):
        await self.client.aclose()
        self.patch1.stop(); self.patch2.stop()
        await self.pool.close()
        await self.admin.execute('DROP SCHEMA ' + self.schema + ' CASCADE')
        await self.admin.close()

    async def search(self, conditions=None, **kwargs):
        async with self.pool.acquire() as conn:
            return await search_inventory(conn, [SoftwareFilter(**v) for v in (conditions or [])], **kwargs)

    async def report(self, items, complete=None, errors=None, when=None, device=1):
        payload = SoftwareReport(hostname='test', ip_address='192.0.2.21', collected_at=when or datetime.now(timezone.utc), items=items,
                                 complete_sources=complete or [], errors=errors or [], os_family='windows')
        async with self.pool.acquire() as conn:
            return await save_inventory(conn, device, payload)

    async def test_filters_sort_pagination_and_alias(self):
        all_rows = await self.search(page_size=20)
        self.assertEqual(all_rows['total'], 207)
        self.assertEqual(len(all_rows['items']), 20)
        for name in ('nodejs', 'Node.js'):
            found = await self.search([{'field': 'software_name', 'value': name}], sort='ip_address', direction='desc')
            self.assertEqual(found['total'], 3)
            self.assertEqual(found['items'][0]['ip_address'], '192.0.2.23')
        found = await self.search([{'field': 'software_name', 'value': 'tomcat'}, {'field': 'software_version', 'op': 'equals', 'value': '10.1.39'}])
        self.assertEqual(found['total'], 2)
        self.assertEqual((await self.search(os_family='linux', freshness='stale'))['total'], 69)
        self.assertEqual((await self.search([{'field': 'software_name', 'value': '%'}]))['total'], 0)
        self.assertEqual((await self.search([{'field': 'software_version', 'op': 'is_empty'}]))['total'], 1)
        self.assertEqual((await self.search(page=999))['page'], 5)
        self.assertEqual((await self.search([{'field': 'server_name', 'op': 'starts_with', 'value': 'MBCO'}]))['total'], 138)
        self.assertEqual((await self.search([{'field': 'server_name', 'op': 'not_contains', 'value': 'MBCO'}]))['total'], 69)
        self.assertEqual((await self.search([{'field': 'ip_address', 'op': 'equals', 'value': '192.0.2.21'}]))['total'], 69)

    async def test_snapshot_replaces_only_complete_sources_and_ignores_old(self):
        when = datetime.now(timezone.utc)
        await self.report([{'name': 'Apache Tomcat', 'version': '11.0.2', 'source': 'tomcat'}], ['tomcat'], when=when)
        found = await self.search([{'field': 'software_name', 'value': 'tomcat'}], device_id=1)
        self.assertEqual([r['software_version'] for r in found['items']], ['11.0.2'])
        self.assertEqual((await self.search(device_id=1))['total'], 69)
        await self.report([], errors=['tomcat failed'])
        self.assertEqual((await self.search(device_id=1))['total'], 69)
        ignored = await self.report([], ['tomcat'], when=when - timedelta(minutes=10))
        self.assertEqual(ignored['status'], 'ignored')
        await self.report([], ['tomcat'])
        self.assertEqual((await self.search([{'field': 'software_name', 'value': 'tomcat'}], device_id=1))['total'], 0)

    async def test_deduplication_multi_installation_and_concurrency(self):
        entries = [{'name': 'Custom', 'version': '2', 'source': 'configured', 'installation_path': '/a'}, {'name': 'Custom', 'version': '2', 'source': 'configured', 'installation_path': '/b'}]
        when = datetime.now(timezone.utc)
        outcomes = await asyncio.gather(*[self.report(entries + entries, ['configured'], when=when) for _ in range(3)])
        self.assertEqual(sum(r['status'] == 'ok' for r in outcomes), 1)
        found = await self.search([{'field': 'software_name', 'value': 'Custom'}])
        self.assertEqual(found['total'], 1)
        self.assertEqual(len(found['items'][0]['installations']), 2)

    async def test_schema_is_additive_and_coverage(self):
        async with self.pool.acquire() as conn:
            await init_inventory_schema(conn)
            self.assertEqual(await conn.fetchval('SELECT COUNT(*) FROM devices'), 4)
            self.assertEqual(await conn.fetchval('SELECT name FROM users'), 'untouched-admin')
            coverage = await inventory_coverage(conn)
        self.assertEqual(coverage['reported'], 3)
        self.assertEqual(coverage['attention'], 2)

    async def test_http_auth_validation_and_csv(self):
        self.assertEqual((await self.client.get('/api/software')).status_code, 401)
        response = await self.client.get('/api/software', headers=self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['total'], 207)
        self.assertEqual((await self.client.get('/api/software?sort=bad', headers=self.headers)).status_code, 400)
        self.assertEqual((await self.client.get('/api/software?page_size=10000', headers=self.headers)).status_code, 422)
        response = await self.client.get('/api/software/export', headers=self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.text.splitlines()), 208)
        self.assertEqual((await self.client.post('/api/software', headers=self.headers, json={})).status_code, 405)

    async def test_export_limit_and_disabled_servers(self):
        async with self.pool.acquire() as conn:
            await conn.execute("UPDATE devices SET enabled=FALSE WHERE id=2")
            self.assertEqual((await search_inventory(conn, []))['total'], 138)
            await conn.execute('''INSERT INTO software_inventory(device_id,fingerprint,name,version,source,first_seen,last_seen)
                SELECT 1,md5(n::text),'Fixture '||n,'1','configured',NOW(),NOW() FROM generate_series(1,10001) n''')
        response = await self.client.get('/api/software/export', headers=self.headers)
        self.assertEqual(response.status_code, 400)
        self.assertIn('10,000', response.json()['detail'])

    async def test_agent_endpoint_auth_unknown_host_and_persistence(self):
        data = {'hostname': 'ignored-name', 'ip_address': '192.0.2.21', 'collected_at': datetime.now(timezone.utc).isoformat(), 'items': [{'name': 'PHP', 'version': '8.4.2', 'source': 'registry'}], 'complete_sources': ['registry']}
        self.assertEqual((await self.client.post('/api/agent/software', json=data)).status_code, 403)
        response = await self.client.post('/api/agent/software', json=data, headers={'X-Agent-Key': agent_routes.AGENT_API_KEY})
        self.assertEqual(response.status_code, 200)
        async with self.pool.acquire() as conn:
            self.assertEqual(await conn.fetchval('SELECT name FROM devices WHERE id=1'), 'MBCO-MES2')
        data['ip_address'] = '192.0.2.250'
        self.assertEqual((await self.client.post('/api/agent/software', json=data, headers={'X-Agent-Key': agent_routes.AGENT_API_KEY})).status_code, 409)


if __name__ == '__main__':
    unittest.main()
