"""Loopback-only preview using synthetic fixtures. No production DB or collectors."""
import argparse
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'backend'), str(ROOT / 'tests')]

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
import uvicorn
import app as backend_app
import database
from api import routes
from security.cve_checker import CVEChecker
from security_fixtures import DEVICES, sample_feed

preview = FastAPI(title='NetGuard synthetic security preview')
completed = set()
cache = tempfile.TemporaryDirectory(prefix='netguard-security-preview-')
(Path(cache.name) / 'nvdcve-preview.json').write_text(json.dumps(sample_feed()), encoding='utf-8')
checker = CVEChecker()
checker.cache_dir = Path(cache.name)
backend_app.cve_checker = checker


async def inventory():
    return DEVICES, set(completed)


class PreviewConnection:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass

    async def execute(self, sql, cve_id):
        if 'INSERT INTO cve_completions' in sql:
            completed.add(cve_id)
        elif 'DELETE FROM cve_completions' in sql:
            completed.discard(cve_id)
        else:
            raise RuntimeError('Preview does not support database writes')


class PreviewPool:
    def acquire(self):
        return PreviewConnection()


async def preview_pool():
    return PreviewPool()


routes._security_inventory = inventory
database.get_db_pool = preview_pool
for route in routes.router.routes:
    if route.path == '/security/search' or route.path.startswith('/security/cves'):
        preview.router.add_api_route('/api' + route.path, route.endpoint, methods=list(route.methods))


@preview.middleware('http')
async def preview_identity(request: Request, call_next):
    request.state.user = {'role': 'admin' if request.headers.get('authorization') == 'Bearer preview-admin' else 'operator'}
    return await call_next(request)


@preview.get('/', response_class=HTMLResponse)
async def index(role: str = 'admin'):
    role = 'operator' if role == 'operator' else 'admin'
    user = json.dumps({'username': 'preview-' + role, 'full_name': '미리보기', 'role': role})
    boot = f"<script>localStorage.setItem('ng_token','preview-{role}');localStorage.setItem('ng_user',JSON.stringify({user}));location.hash='security';</script>"
    html = (ROOT / 'frontend' / 'index.html').read_text(encoding='utf-8')
    html = html.replace('<head>', '<head>' + boot)
    html = html.replace('<h1>취약점 검색</h1>', '<h1>취약점 검색 <small style="font-size:11px;color:#d6c59a">샘플 데이터 · 로컬 미리보기</small></h1>')
    return html


@preview.get('/api/devices')
async def devices():
    return DEVICES


@preview.get('/api/events')
@preview.get('/api/metrics/latest')
async def empty_list():
    return []


@preview.get('/api/dashboard/summary')
@preview.get('/api/thresholds/effective')
async def empty_object():
    return {}


@preview.get('/api/security/checks/summary')
async def checks():
    return {'summary': {}, 'latest_runs': [], 'item_summary': [], 'server_summary': []}


@preview.websocket('/ws')
async def socket_endpoint(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            await websocket.receive_text()
            await websocket.send_json({'type': 'pong'})
    except WebSocketDisconnect:
        pass


preview.mount('/css', StaticFiles(directory=str(ROOT / 'frontend' / 'css')))
preview.mount('/js', StaticFiles(directory=str(ROOT / 'frontend' / 'js')))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, default=8769)
    args = parser.parse_args()
    try:
        uvicorn.run(preview, host='127.0.0.1', port=args.port)
    finally:
        cache.cleanup()
