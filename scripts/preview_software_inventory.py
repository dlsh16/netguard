"""Loopback-only synthetic inventory preview; requires a disposable PostgreSQL DSN."""
import argparse
import os
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlparse
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'backend'), str(ROOT / 'tests')]
import asyncpg
import uvicorn
import preview_security_search as base
from api import software_routes
from software_fixtures import seed, DEVICES

pool = None


@asynccontextmanager
async def lifespan(app):
    global pool
    dsn = os.environ['NETGUARD_SOFTWARE_TEST_DSN']
    if urlparse(dsn).hostname not in ('127.0.0.1', 'localhost'):
        raise RuntimeError('Preview requires a disposable loopback database')
    schema = 'preview_software_' + uuid4().hex
    admin = await asyncpg.connect(dsn)
    await admin.execute('CREATE SCHEMA ' + schema)
    pool = await asyncpg.create_pool(dsn, min_size=1, max_size=4, server_settings={'search_path': schema})
    try:
        async with pool.acquire() as conn:
            await seed(conn)
        yield
    finally:
        await pool.close()
        await admin.execute('DROP SCHEMA ' + schema + ' CASCADE')
        await admin.close()


async def preview_pool():
    return pool


original_index = base.index


async def index(role: str = 'admin', view: str = 'processes'):
    html = await original_index(role, 'dashboard')
    html = html.replace("location.hash='dashboard'", "location.hash='processes'")
    return html.replace('<h1>소프트웨어 인벤토리</h1>', '<h1>소프트웨어 인벤토리 <small style="font-size:11px;color:#e9b865">샘플 데이터 · 로컬 미리보기</small></h1>')


base.DEVICES = [dict(id=id, name=name, ip_address=ip, os_version=version, type='server') for id, name, ip, version in DEVICES]
base.preview.router.routes = [route for route in base.preview.router.routes if route.path != '/']
base.preview.add_api_route('/', index, response_class=base.HTMLResponse)
base.preview.router.lifespan_context = lifespan
software_routes.get_db_pool = preview_pool
base.preview.include_router(software_routes.router)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, default=8770)
    args = parser.parse_args()
    uvicorn.run(base.preview, host='127.0.0.1', port=args.port)
