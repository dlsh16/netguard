"""Operational features: synthetic fixtures and disposable loopback DB only."""
import asyncio
import base64
from datetime import datetime, timedelta, timezone
from io import BytesIO
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import AsyncMock, patch
from urllib.parse import urlparse
from uuid import uuid4
from zipfile import ZipFile
from xml.etree import ElementTree as ET

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'agent'))
sys.path.insert(0,str(ROOT/'backend'))
import asyncpg
import httpx
from fastapi import FastAPI, Request
from api import check_job_routes, advisory_routes, asset_routes, routes
from operations_schema import init_operations_schema
from security import check_reports
from security.advisories import parse_rss, match_reason, save_advisories
from switch_links import observe, monitor_links
from asset_export import build_asset_workbook
from remote_checks import command_for

RSS='''<?xml version="1.0"?><rss><channel><item><title>PHP 보안 업데이트 권고</title>
<link>https://www.boho.or.kr/kr/bbs/view.do?nttId=1&amp;pageIndex=1</link>
<pubDate> 2026-11-27 </pubDate><description>&lt;p&gt;PHP 제품 버전 확인&lt;/p&gt;</description></item></channel></rss>'''.encode('utf-8')
CSV='항목ID,점검항목,분류,점검결과,상세내용,조치권고사항\nU-1,권한 점검,계정,취약,&lt;fixture&gt;,검토\n'.encode('utf-8-sig')


class OperationsUnitTests(unittest.TestCase):
    def test_linux_report_failure_status_is_not_na(self):
        data=CSV.decode('utf-8-sig').replace('취약','불량').encode('utf-8')
        self.assertEqual(check_reports.parse_report('remote_security_1.csv',data)['rows'][0]['status'],'fail')

    def test_rss_bom_korean_date_stable_id_and_no_html(self):
        item=parse_rss(b'\xef\xbb\xbf'+RSS)[0]
        self.assertEqual(item['title'],'PHP 보안 업데이트 권고')
        self.assertEqual(item['published_at'].isoformat(),'2026-11-27T00:00:00+09:00')
        self.assertEqual(item['summary'],'PHP 제품 버전 확인')
        self.assertEqual(item['id'],parse_rss(RSS.replace(b'pageIndex=1',b'pageIndex=2'))[0]['id'])
        for data in (b'<html>login</html>',b'<!DOCTYPE a><rss><channel/></rss>',RSS.replace(b'https://www.boho.or.kr',b'https://attacker.invalid')):
            with self.assertRaises(ValueError):parse_rss(data)

    def test_candidate_not_confirmed_and_false_substrings(self):
        item=parse_rss(RSS)[0]
        self.assertIn('버전 검증 필요',match_reason(item,{'software_name':'php-cli'}))
        self.assertIsNone(match_reason(item,{'software_name':'graphpaper'}))
        self.assertIsNone(match_reason(item,{'software_name':'Node.js'}))

    def test_link_debounce_initial_baseline_missing_and_logical(self):
        now=datetime.now(timezone.utc)
        port=dict(name='GigabitEthernet1/0/26',admin_status='up',status='up')
        row,event=observe(None,port,now);self.assertIsNone(event)
        row,event=observe(row,port,now);self.assertIsNone(event)
        row,event=observe(row,dict(port,status='down'),now);self.assertIsNone(event)
        row,event=observe(row,dict(port,status='unknown'),now);self.assertIsNone(event)
        row,event=observe(row,dict(port,status='down'),now);self.assertIsNone(event)
        row,event=observe(row,dict(port,status='down'),now);self.assertEqual(event,('up','down'))
        row,event=observe(row,dict(port,status='down'),now);self.assertIsNone(event)
        for name in ('Vlan-interface1','Null0','LoopBack0'):
            _,event=observe(row,dict(port,name=name),now);self.assertIsNone(event)
        _,event=observe(row,dict(port,admin_status='down'),now);self.assertIsNone(event)

    def test_workbook_valid_unicode_no_credentials_or_formula_injection(self):
        devices=[dict(id=1,name='=DANGEROUS()',type='server',ip_address='192.0.2.1',location='전산실',os_version='Linux'),
                 dict(id=2,name='스위치',type='switch',ip_address='192.0.2.2'),dict(id=3,name='UPS',type='ups')]
        data=build_asset_workbook(devices,[dict(device_id=1,name='PHP',version='8.2.1')])
        with ZipFile(BytesIO(data)) as z:
            self.assertIsNone(z.testzip())
            doc=ET.fromstring(z.read('xl/worksheets/sheet1.xml'))
            ns={'m':'http://schemas.openxmlformats.org/spreadsheetml/2006/main'}
            self.assertFalse(doc.findall('.//m:f',ns))
            text=' '.join(doc.itertext())
            self.assertIn('=DANGEROUS()',text);self.assertIn('PHP 8.2.1',text);self.assertIn('전산실',text)
            self.assertNotIn('community',text)
            self.assertEqual(len(doc.findall('.//m:row',ns)),6)

    def test_remote_command_allowlist(self):
        for kind,job in [('bash',1),('security','1;id'),('security',-1)]:
            with self.assertRaises(ValueError):command_for(kind,job,Path('out'))
        self.assertNotIn('shell',command_for('security',1,Path('out')))


@unittest.skipUnless(os.getenv('NETGUARD_SOFTWARE_TEST_DSN'),'Disposable PostgreSQL DSN not set')
class OperationsApiTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        dsn=os.environ['NETGUARD_SOFTWARE_TEST_DSN']
        if urlparse(dsn).hostname not in ('localhost','127.0.0.1'):raise RuntimeError('Loopback test DB only')
        self.schema='test_operations_'+uuid4().hex
        self.admin=await asyncpg.connect(dsn)
        await self.admin.execute('CREATE SCHEMA '+self.schema)
        self.pool=await asyncpg.create_pool(dsn,min_size=1,max_size=5,server_settings={'search_path':self.schema})
        async with self.pool.acquire() as c:
            await c.execute('''CREATE TABLE devices(id SERIAL PRIMARY KEY,name TEXT,type TEXT,ip_address INET,
                snmp_version TEXT,os_version TEXT,location TEXT,enabled BOOLEAN DEFAULT TRUE,updated_at TIMESTAMPTZ DEFAULT NOW());
                CREATE TABLE events(id SERIAL PRIMARY KEY,time TIMESTAMPTZ DEFAULT NOW(),device_id INTEGER REFERENCES devices(id),
                    severity TEXT,category TEXT,message TEXT,status TEXT,resolved_at TIMESTAMPTZ);
                CREATE TABLE check_runs(id SERIAL PRIMARY KEY,run_type TEXT,source_tool TEXT,report_title TEXT,status TEXT,notes TEXT,
                    started_at TIMESTAMPTZ,completed_at TIMESTAMPTZ DEFAULT NOW());
                CREATE TABLE check_items(id SERIAL PRIMARY KEY,code TEXT UNIQUE,name TEXT,category TEXT,severity TEXT,description TEXT);
                CREATE TABLE check_results(id SERIAL PRIMARY KEY,run_id INT,device_id INT,check_item_id INT,result_status TEXT,
                    result_value TEXT,evidence TEXT,recommendation TEXT,checked_at TIMESTAMPTZ DEFAULT NOW(),UNIQUE(run_id,device_id,check_item_id));
                CREATE TABLE report_files(id SERIAL PRIMARY KEY,run_id INT,original_name TEXT,stored_name TEXT,mime_type TEXT,size_bytes BIGINT,storage_path TEXT);
                INSERT INTO devices(name,type,ip_address,snmp_version,os_version) VALUES
                    ('서버 A','server','192.0.2.1','agent','Linux'),('서버 B','server','192.0.2.2','agent','Windows'),
                    ('스위치','switch','192.0.2.3','v2c','Comware');''')
            from software_inventory import init_inventory_schema
            await init_inventory_schema(c)
            await init_operations_schema(c)
            await init_operations_schema(c)
        self.patches=[patch.object(module,'get_db_pool',AsyncMock(return_value=self.pool)) for module in (check_job_routes,advisory_routes,asset_routes)]
        for p in self.patches:p.start()
        self.temp=tempfile.TemporaryDirectory()
        p=patch.object(check_reports,'REPORT_STORAGE_DIR',Path(self.temp.name));p.start();self.patches.append(p)
        app=FastAPI()
        @app.middleware('http')
        async def user(request:Request,call_next):
            request.state.user={'role':request.headers.get('X-Test-Role','admin'),'sub':'test-admin'}
            return await call_next(request)
        app.include_router(check_job_routes.router);app.include_router(advisory_routes.router);app.include_router(asset_routes.router)
        self.client=httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://test')

    async def asyncTearDown(self):
        await self.client.aclose()
        for p in self.patches:p.stop()
        self.temp.cleanup()
        await self.pool.close()
        await self.admin.execute('DROP SCHEMA '+self.schema+' CASCADE')
        await self.admin.close()

    async def enroll(self,device=1):
        r=await self.client.post('/api/security/checks/agents/{}/enroll'.format(device))
        self.assertEqual(r.status_code,200,r.text)
        return {'X-Check-Token':r.json()['remote_checks']['token']}

    async def test_admin_authorization_and_token_isolation(self):
        for path,body in [('/api/security/checks/agents/1/enroll',{}),('/api/security/checks/agents/1/jobs',{'run_type':'security'}),('/api/security/advisories/sync',{})]:
            self.assertEqual((await self.client.post(path,json=body,headers={'X-Test-Role':'operator'})).status_code,403)
        self.assertEqual((await self.client.get('/api/assets/export.xlsx',headers={'X-Test-Role':'operator'})).status_code,403)
        self.assertEqual((await self.client.post('/api/agent/check-jobs/poll')).status_code,403)
        self.assertEqual((await self.client.post('/api/security/checks/agents/3/enroll')).status_code,400)

    async def test_claim_once_store_result_idempotently_and_bind_existing_device(self):
        token=await self.enroll()
        self.assertIsNone((await self.client.post('/api/agent/check-jobs/poll',headers=token)).json()['job'])
        r=await self.client.post('/api/security/checks/agents/1/jobs',json={'run_type':'security'})
        self.assertEqual(r.status_code,200,r.text);job=r.json()['id']
        self.assertEqual((await self.client.post('/api/security/checks/agents/1/jobs',json={'run_type':'maintenance'})).status_code,409)
        claims=await asyncio.gather(*[self.client.post('/api/agent/check-jobs/poll',headers=token) for _ in range(2)])
        self.assertEqual(sum(bool(c.json()['job']) for c in claims),1)
        other=await self.enroll(2)
        payload={'status':'completed','content_base64':base64.b64encode(CSV).decode()}
        self.assertEqual((await self.client.post('/api/agent/check-jobs/{}/result'.format(job),json=payload,headers=other)).status_code,404)
        for _ in range(2):
            result=await self.client.post('/api/agent/check-jobs/{}/result'.format(job),json=payload,headers=token)
            self.assertEqual(result.status_code,200,result.text)
        async with self.pool.acquire() as c:
            self.assertEqual(await c.fetchval('SELECT count(*) FROM devices'),3)
            self.assertEqual(await c.fetchval('SELECT count(*) FROM check_runs'),1)
            self.assertEqual(await c.fetchval('SELECT device_id FROM check_results'),1)
            self.assertIsNotNone(await c.fetchval('SELECT started_at FROM check_runs'))
        r=await self.client.get('/api/security/checks/jobs?device_id=2')
        self.assertFalse(r.json()['items'])

    async def test_offline_expiry_cancel_and_no_running_replay(self):
        token=await self.enroll()
        self.assertEqual((await self.client.post('/api/security/checks/agents/1/jobs',json={'run_type':'security'})).status_code,409)
        await self.client.post('/api/agent/check-jobs/poll',headers=token)
        row=(await self.client.post('/api/security/checks/agents/1/jobs',json={'run_type':'maintenance'})).json()
        async with self.pool.acquire() as c:
            await c.execute("UPDATE agent_check_jobs SET requested_at=NOW()-INTERVAL '20 minutes'")
        self.assertIsNone((await self.client.post('/api/agent/check-jobs/poll',headers=token)).json()['job'])
        r=await self.client.get('/api/security/checks/jobs');self.assertEqual(r.json()['items'][0]['status'],'expired')
        row=(await self.client.post('/api/security/checks/agents/1/jobs',json={'run_type':'maintenance'})).json()
        self.assertEqual((await self.client.post('/api/security/checks/jobs/{}/cancel'.format(row['id']))).status_code,200)

    async def test_future_provider_uses_own_sync_state(self):
        from security import advisories
        entry=dict(parse_rss(RSS)[0],id='fixture-api-id',provider='fixture-api')
        provider=type('FixtureProvider',(),{'fetch':AsyncMock(return_value=[entry])})
        with patch.dict(advisories.PROVIDERS,{'fixture-api':provider}):
            result=await advisories.sync_advisories(self.pool,'fixture-api')
        self.assertEqual(result['count'],1)
        async with self.pool.acquire() as conn:
            self.assertEqual(await conn.fetchval('SELECT provider FROM advisory_sync'),'fixture-api')

    async def test_rss_import_search_and_preserve_after_bad_import(self):
        for _ in range(2):
            r=await self.client.post('/api/security/advisories/import',files={'file':('rss.xml',RSS,'text/xml')})
            self.assertEqual(r.status_code,200,r.text)
        r=await self.client.get('/api/security/advisories?q=PHP')
        self.assertEqual(r.status_code,200,r.text);self.assertEqual(r.json()['total'],1)
        self.assertTrue(r.json()['sync']['succeeded_at'])
        async with self.pool.acquire() as c:
            await c.execute("INSERT INTO software_inventory(device_id,fingerprint,name,version,source,first_seen,last_seen) VALUES(1,$1,'php-cli','8.2.1','rpm',NOW(),NOW())",'b'*64)
        r=await self.client.get('/api/security/advisories')
        self.assertEqual(r.json()['items'][0]['matches'][0]['server_name'],'서버 A')
        self.assertEqual((await self.client.post('/api/security/advisories/import',files={'file':('rss.xml',b'<html>error</html>')})).status_code,400)
        self.assertEqual((await self.client.get('/api/security/advisories')).json()['total'],1)

    async def test_link_state_persisted_one_down_and_one_up(self):
        def fixture(state):return [dict(device_id=3,device='스위치',type='switch',status='online',metrics={'interfaces':[dict(index=26,name='GigabitEthernet1/0/26',admin_status='up',status=state)]})]
        for state in ('up','up','down','unknown','down'):
            self.assertFalse((await monitor_links(self.pool,fixture(state)))[0])
        events,_=await monitor_links(self.pool,fixture('down'));self.assertEqual(len(events),1)
        for _ in range(3):self.assertFalse((await monitor_links(self.pool,fixture('down')))[0])
        self.assertFalse((await monitor_links(self.pool,fixture('up')))[0])
        events,closed=await monitor_links(self.pool,fixture('up'));self.assertEqual(len(events),1);self.assertEqual(len(closed),1)
        async with self.pool.acquire() as c:
            self.assertEqual(await c.fetchval("SELECT count(*) FROM events WHERE message LIKE '%DOWN%'") ,2)
            self.assertEqual(await c.fetchval("SELECT count(*) FROM events WHERE status='resolved'"),1)

    async def test_asset_download(self):
        r=await self.client.get('/api/assets/export.xlsx')
        self.assertEqual(r.status_code,200,r.text[:100] if r.status_code!=200 else '')
        self.assertTrue(r.content.startswith(b'PK'))
        self.assertIn('attachment',r.headers['content-disposition'])

    async def test_time_filters_and_running_timeout_not_reclaimed(self):
        self.assertEqual((await self.client.get('/api/security/checks/jobs?since=2026-11-27')).status_code,400)
        token=await self.enroll()
        await self.client.post('/api/agent/check-jobs/poll',headers=token)
        await self.client.post('/api/security/checks/agents/1/jobs',json={'run_type':'security'})
        await self.client.post('/api/agent/check-jobs/poll',headers=token)
        async with self.pool.acquire() as c:
            await c.execute("UPDATE agent_check_jobs SET started_at=NOW()-INTERVAL '46 minutes'")
        self.assertIsNone((await self.client.post('/api/agent/check-jobs/poll',headers=token)).json()['job'])
        self.assertEqual((await self.client.get('/api/security/checks/jobs')).json()['items'][0]['status'],'unknown')


if __name__=='__main__':unittest.main()
