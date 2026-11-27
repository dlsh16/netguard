"""Loopback-only preview, synthetic data. No production Agent, collectors or credentials."""
import argparse
from contextlib import asynccontextmanager
import sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'backend'),str(ROOT/'tests')]
import uvicorn
import preview_security_search as base
from test_operations import OperationsApiTests,RSS,CSV
from api import check_job_routes,advisory_routes,asset_routes,routes
from security.advisories import parse_rss,save_advisories
from security.check_reports import save_report

fixture=OperationsApiTests()


@asynccontextmanager
async def lifespan(app):
    await fixture.asyncSetUp()
    try:
        async with fixture.pool.acquire() as conn:
            await save_advisories(conn,parse_rss(RSS))
            await conn.execute("INSERT INTO software_inventory(device_id,fingerprint,name,version,source,first_seen,last_seen) VALUES(1,$1,'PHP','8.2.1','rpm',NOW(),NOW())",'a'*64)
            await conn.execute("INSERT INTO agent_check_access(device_id,token_hash,last_seen) VALUES(1,$1,NOW()),(2,$2,NOW())",'fixture-only-1','fixture-only-2')
            await conn.execute("INSERT INTO agent_check_jobs(device_id,run_type,requested_by,status,started_at,completed_at,detail) VALUES(2,'maintenance','preview','completed',NOW()-INTERVAL '10 minutes',NOW(),'샘플 실행 이력')")
            report=await save_report(conn,'sample.csv',CSV,{'device_id':2,'hostname':'서버 B','run_type':'maintenance'})
            await conn.execute('UPDATE agent_check_jobs SET run_id=$1 WHERE device_id=2',report['id'])
            base.DEVICES=[dict(r) for r in await conn.fetch('SELECT id,name,type,host(ip_address) AS ip_address,os_version,snmp_version FROM devices')]
        yield
    finally:
        await fixture.asyncTearDown()


original_index=base.index
async def index(role='admin',view='security'):
    html=await original_index(role,view)
    return html.replace('<h1>보안 업데이트 권고</h1>','<h1>보안 업데이트 권고 <small>샘플 · 로컬 미리보기</small></h1>')


base.preview.router.routes=[r for r in base.preview.router.routes if r.path!='/']
base.preview.add_api_route('/',index,response_class=base.HTMLResponse)
base.preview.router.lifespan_context=lifespan
base.preview.include_router(check_job_routes.router)
base.preview.include_router(advisory_routes.router)
base.preview.include_router(asset_routes.router)

@base.preview.get('/api/security/checks/runs')
async def runs(): return []

@base.preview.get('/api/security/checks/runs/{run_id}/results')
async def results(run_id:int):
    from unittest.mock import AsyncMock,patch
    with patch.object(base.database,'get_db_pool',AsyncMock(return_value=fixture.pool)):
        return await routes.get_check_run_results(run_id)

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port',type=int,default=8772)
    args=parser.parse_args()
    uvicorn.run(base.preview,host='127.0.0.1',port=args.port)
