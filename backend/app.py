"""
NetGuard SNMP Dashboard - FastAPI Backend
"""
import asyncio
import json
import logging
import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from auth.routes import router as auth_router
from config import settings
from collectors.snmp_collector import SNMPCollector
from collectors.env_collector import EnvCollector
from api.routes import router as api_router
from api.agent_routes import get_agent_live_ips, get_agent_live_results, router as agent_router
from alerts.alert_manager import AlertManager
from security.cve_checker import CVEChecker
from database import get_db_pool, close_db_pool, init_db

LOG_DIR = Path(os.environ.get("NETGUARD_LOG_DIR", Path(__file__).parent.parent / "logs"))
LOG_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(LOG_DIR / 'netguard.log', encoding='utf-8')
    ]
)
logger = logging.getLogger('netguard')

app = FastAPI(
    title="NetGuard SNMP Dashboard API",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url=None
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── JWT auth middleware ────────────────────────────────────────────────────────
_PUBLIC_PREFIXES = ("/css/", "/js/", "/static/", "/favicon", "/api/agent/")
_PUBLIC_EXACT    = {"/", "/login", "/api/auth/login", "/api/health", "/health"}

@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    path = request.url.path
    if path in _PUBLIC_EXACT or any(path.startswith(p) for p in _PUBLIC_PREFIXES):
        return await call_next(request)
    if path.startswith("/api/"):
        auth  = request.headers.get("Authorization", "")
        token = auth[7:] if auth.startswith("Bearer ") else ""
        if not token:
            return JSONResponse({"detail": "인증이 필요합니다"}, status_code=401)
        try:
            from auth.jwt_handler import decode_token
            request.state.user = decode_token(token, settings.JWT_SECRET)
        except Exception:
            return JSONResponse({"detail": "인증이 필요합니다"}, status_code=401)
    return await call_next(request)

# ── Static assets (serve /css/* and /js/* at root so relative HTML paths work) ─
FRONTEND_DIR = Path(__file__).parent.parent / "frontend"
if FRONTEND_DIR.exists():
    if (FRONTEND_DIR / "css").exists():
        app.mount("/css", StaticFiles(directory=str(FRONTEND_DIR / "css")), name="css")
    if (FRONTEND_DIR / "js").exists():
        app.mount("/js", StaticFiles(directory=str(FRONTEND_DIR / "js")), name="js")
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="static")

app.include_router(auth_router,  prefix="/api")
app.include_router(api_router,   prefix="/api")
app.include_router(agent_router)

# Global services
snmp_collector: Optional[SNMPCollector] = None
env_collector: Optional[EnvCollector] = None
alert_manager: Optional[AlertManager] = None
cve_checker: Optional[CVEChecker] = None

# WebSocket connection manager
class ConnectionManager:
    def __init__(self):
        self.active: List[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.append(ws)
        logger.info(f"WS connected: {ws.client}")

    def disconnect(self, ws: WebSocket):
        if ws in self.active:
            self.active.remove(ws)

    async def broadcast(self, data: dict):
        dead = []
        for ws in self.active:
            try:
                await ws.send_json(data)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)

manager = ConnectionManager()
latest_metrics_payload: Optional[dict] = None
switch_port_alerts_initialized = False


@app.on_event("startup")
async def startup():
    logger.info("NetGuard starting up...")

    await init_db()

    global snmp_collector, env_collector, alert_manager, cve_checker
    snmp_collector = SNMPCollector()
    env_collector = EnvCollector()
    alert_manager = AlertManager()
    cve_checker = CVEChecker()

    asyncio.create_task(collection_loop())
    logger.info("NetGuard started successfully")


@app.on_event("shutdown")
async def shutdown():
    await close_db_pool()
    logger.info("NetGuard shutdown complete")


async def collection_loop():
    """Main SNMP polling loop — runs every 60 seconds."""
    global latest_metrics_payload, switch_port_alerts_initialized
    while True:
        try:
            pool = await get_db_pool()
            async with pool.acquire() as conn:
                devices = [dict(r) for r in await conn.fetch(
                    "SELECT * FROM devices WHERE enabled = TRUE ORDER BY name"
                )]

            agent_ips = get_agent_live_ips()
            snmp_devices = [
                d for d in devices
                if str(d.get('snmp_version', '')).lower() != 'agent'
                and str(d.get('ip_address')) not in agent_ips
            ]
            snmp_collector.set_devices(snmp_devices)
            snmp_results = await snmp_collector.collect_all()
            env_data = await env_collector.collect()

            await _save_metrics(pool, devices, snmp_results, env_data)

            agent_results = get_agent_live_results()
            db_agent_results = await _load_recent_agent_results(pool, devices, agent_results)
            results = snmp_results + agent_results + db_agent_results
            _attach_device_identity(devices, results)
            all_alerts = []
            for device_data in results:
                try:
                    alerts = await alert_manager.evaluate(device_data)
                    if alerts:
                        saved = await _save_events(pool, devices, alerts)
                        all_alerts.extend(saved)
                except Exception as e:
                    logger.error(
                        f"Alert evaluation failed for {device_data.get('device')}: {e}",
                        exc_info=True,
                    )

            resolved_event_ids = await _resolve_switch_port_events(
                pool,
                devices,
                results,
                clear_existing=not switch_port_alerts_initialized,
            )
            switch_port_alerts_initialized = True

            if all_alerts:
                await manager.broadcast({"type": "alert", "alerts": all_alerts})
            if resolved_event_ids:
                await manager.broadcast({
                    "type": "events_resolved",
                    "event_ids": resolved_event_ids,
                })

            latest_metrics_payload = {
                "type": "metrics",
                "timestamp": datetime.now().isoformat(),
                "devices": results,
                "environment": env_data
            }
            await manager.broadcast(latest_metrics_payload)

        except Exception as e:
            logger.error(f"Collection loop error: {e}", exc_info=True)

        await asyncio.sleep(60)


def _attach_device_identity(devices: list, results: list):
    """Add stable device_id/type/ip metadata to live payloads."""
    by_ip = {str(d.get('ip_address')): d for d in devices}
    by_name = {d.get('name'): d for d in devices}
    for result in results:
        device = by_ip.get(str(result.get('ip'))) or by_name.get(result.get('device'))
        if not device:
            continue
        result['device_id'] = device.get('id')
        result['device'] = device.get('name', result.get('device'))
        result['ip'] = str(device.get('ip_address', result.get('ip')))
        result['type'] = device.get('type', result.get('type'))


async def _apply_switch_error_baselines(pool, results: list):
    device_ids = [
        int(r['device_id']) for r in results
        if r.get('type') == 'switch' and r.get('device_id') is not None
    ]
    if not device_ids:
        return

    async with pool.acquire() as conn:
        rows = await conn.fetch("""
            SELECT device_id, if_index, in_baseline, out_baseline
            FROM switch_error_baselines
            WHERE device_id = ANY($1::int[])
        """, device_ids)

    baselines = {
        (int(r['device_id']), int(r['if_index'])): r
        for r in rows
    }

    for result in results:
        if result.get('type') != 'switch' or result.get('device_id') is None:
            continue
        device_id = int(result['device_id'])
        for iface in result.get('metrics', {}).get('interfaces', []):
            if_index = iface.get('index')
            if if_index is None:
                continue
            baseline = baselines.get((device_id, int(if_index)))
            raw_in = int(iface.get('in_errors', 0) or 0)
            raw_out = int(iface.get('out_errors', 0) or 0)
            iface['raw_in_errors'] = raw_in
            iface['raw_out_errors'] = raw_out
            if not baseline:
                continue
            iface['in_errors'] = max(raw_in - int(baseline['in_baseline'] or 0), 0)
            iface['out_errors'] = max(raw_out - int(baseline['out_baseline'] or 0), 0)
            iface['error_baseline_at'] = baseline.get('updated_at')


async def _load_recent_agent_results(pool, devices: list, live_agent_results: list) -> list:
    """Restore agent live state from recent DB metrics after service restarts."""
    live_ids = {
        r.get('device_id') for r in live_agent_results
        if r.get('device_id') is not None
    }
    live_ips = {
        str(r.get('ip')) for r in live_agent_results
        if r.get('ip') is not None
    }
    agent_devices = [
        d for d in devices
        if str(d.get('snmp_version', '')).lower() == 'agent'
        and d.get('id') not in live_ids
        and str(d.get('ip_address')) not in live_ips
    ]
    if not agent_devices:
        return []

    device_ids = [d['id'] for d in agent_devices]
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT DISTINCT ON (device_id, metric_name)
                   device_id, metric_name, value, time
            FROM metrics
            WHERE device_id = ANY($1::int[])
              AND metric_name = ANY($2::text[])
              AND time >= NOW() - INTERVAL '10 minutes'
            ORDER BY device_id, metric_name, time DESC
            """,
            device_ids,
            ['cpu_pct', 'mem_pct', 'disk_max_pct', 'net_in_bps', 'net_out_bps'],
        )

    by_id = {d['id']: {'device': d, 'metrics': {}, 'timestamp': None} for d in agent_devices}
    for row in rows:
        item = by_id.get(row['device_id'])
        if not item:
            continue
        item['metrics'][row['metric_name']] = round(float(row['value']), 1)
        if item['timestamp'] is None or row['time'] > item['timestamp']:
            item['timestamp'] = row['time']

    restored = []
    for device_id, item in by_id.items():
        if not item['metrics']:
            continue
        device = item['device']
        restored.append({
            'device_id': device_id,
            'device': device['name'],
            'ip': str(device['ip_address']),
            'type': device.get('type', 'server'),
            'status': 'online',
            'timestamp': item['timestamp'].isoformat(),
            'metrics': {
                **item['metrics'],
                'disks': [],
                'processes': [],
                'interfaces': [],
            },
        })
    return restored


async def _save_events(pool, devices: list, alerts: list) -> list:
    """Save alerts to DB and return with id/device_name/status fields."""
    device_by_name = {d['name']: d for d in devices}
    saved = []
    async with pool.acquire() as conn:
        for alert in alerts:
            if _is_switch_port_error_event(alert.get('message', '')):
                continue
            device = device_by_name.get(alert['device'])
            try:
                row = await conn.fetchrow("""
                    INSERT INTO events (time, device_id, severity, category, message, status)
                    VALUES (NOW(), $1, $2, $3, $4, 'active')
                    RETURNING id, time
                """, device['id'] if device else None,
                    alert['severity'], alert['category'], alert['message'])
                saved.append({
                    **alert,
                    'id': row['id'],
                    'time': row['time'].isoformat(),
                    'device_name': alert['device'],
                    'status': 'active'
                })
            except Exception as e:
                logger.error(f"Event save failed: {e}")
    return saved


async def _resolve_switch_port_events(
    pool,
    devices: list,
    results: list,
    clear_existing: bool = False,
) -> list[int]:
    """Resolve legacy or recovered switch port-down events."""
    switch_ids = {
        d['id'] for d in devices
        if d.get('type') == 'switch'
    }
    if not switch_ids:
        return []

    up_ports = set()
    switch_interfaces = {}
    switch_by_name = {
        d['name']: d for d in devices
        if d.get('type') == 'switch'
    }
    for result in results:
        if result.get('type') != 'switch':
            continue
        device = switch_by_name.get(result.get('device'))
        if not device:
            continue
        interfaces = result.get('metrics', {}).get('interfaces', [])
        switch_interfaces[device['id']] = interfaces
        for iface in interfaces:
            if iface.get('status') == 'up':
                up_ports.add((device['id'], iface.get('name')))

    resolved_ids = []
    async with pool.acquire() as conn:
        rows = await conn.fetch("""
            SELECT id, device_id, message
            FROM events
            WHERE status IN ('active', 'acknowledged')
              AND device_id = ANY($1::int[])
              AND category = '네트워크'
              AND message LIKE '포트 % 다운 감지'
        """, list(switch_ids))

        for row in rows:
            port_name = _extract_switch_port_name(row['message'])
            should_resolve = clear_existing or (row['device_id'], port_name) in up_ports
            if not should_resolve:
                continue
            await conn.execute("""
                UPDATE events
                SET status = 'resolved', resolved_at = NOW()
                WHERE id = $1
            """, row['id'])
            resolved_ids.append(row['id'])

    return resolved_ids


def _extract_switch_port_name(message: str) -> str:
    prefix = '포트 '
    suffix = ' 다운 감지'
    if message.startswith(prefix) and message.endswith(suffix):
        return message[len(prefix):-len(suffix)]
    return ''


def _iface_name_candidates(iface: dict) -> list[str]:
    names = [
        iface.get('name'),
        iface.get('if_name'),
        iface.get('descr'),
    ]
    return [str(name) for name in names if name]


def _find_iface_by_event_message(message: str, interfaces: list[dict]) -> dict | None:
    candidates = []
    for iface in interfaces:
        for name in _iface_name_candidates(iface):
            candidates.append((name, iface))
    for name, iface in sorted(candidates, key=lambda item: len(item[0]), reverse=True):
        if name and name in message:
            return iface
    return None


async def _save_metrics(pool, devices: list, results: list, env_data: dict):
    """Persist scalar metrics to TimescaleDB."""
    device_by_name = {d['name']: d for d in devices}
    now = datetime.now()
    rows = []
    metadata_rows = []

    for result in results:
        device = device_by_name.get(result['device'])
        if not device:
            continue
        dev_id = device['id']
        m = result.get('metrics', {})
        system = result.get('system') or {}

        if result.get('status') == 'online' and system.get('sys_descr'):
            metadata_rows.append((system['sys_descr'][:200], dev_id))

        for key in ('cpu_pct', 'mem_pct', 'battery_pct', 'load_pct',
                    'input_v', 'output_v', 'temp_c', 'humidity_pct', 'runtime_min'):
            if key in m and m[key] is not None:
                if not _is_valid_metric_value(device, key, m[key]):
                    continue
                rows.append((now, dev_id, key, float(m[key])))

        if m.get('disks'):
            max_disk = max(d['used_pct'] for d in m['disks'])
            rows.append((now, dev_id, 'disk_max_pct', round(max_disk, 1)))

        if result.get('type') == 'switch' and m.get('interfaces'):
            active_ifaces = [i for i in m['interfaces'] if i.get('status') == 'up']
            rows.append((
                now,
                dev_id,
                'net_in_mb',
                round(sum(float(i.get('in_octets', 0) or 0) for i in active_ifaces) / 1024 / 1024, 2),
            ))
            rows.append((
                now,
                dev_id,
                'net_out_mb',
                round(sum(float(i.get('out_octets', 0) or 0) for i in active_ifaces) / 1024 / 1024, 2),
            ))

    # Env collector (Raspberry Pi)
    if env_data and env_data.get('source') != 'disabled':
        rpi = next((d for d in devices if d['type'] in ('rpi', 'env', 'environment', 'sensor')), None)
        if rpi:
            if env_data.get('temp_c') is not None:
                if _is_valid_metric_value(rpi, 'temp_c', env_data['temp_c']):
                    rows.append((now, rpi['id'], 'temp_c', float(env_data['temp_c'])))
            if env_data.get('humidity_pct') is not None:
                if _is_valid_metric_value(rpi, 'humidity_pct', env_data['humidity_pct']):
                    rows.append((now, rpi['id'], 'humidity_pct', float(env_data['humidity_pct'])))

    if rows or metadata_rows:
        try:
            async with pool.acquire() as conn:
                if metadata_rows:
                    await conn.executemany(
                        "UPDATE devices SET os_version=$1, updated_at=NOW() WHERE id=$2",
                        metadata_rows
                    )
                if rows:
                    await conn.executemany(
                        "INSERT INTO metrics(time, device_id, metric_name, value) VALUES($1,$2,$3,$4)",
                        rows
                    )
        except Exception as e:
            logger.error(f"Metric save failed: {e}")


def _is_valid_metric_value(device: dict, key: str, value) -> bool:
    if key not in ('temp_c', 'humidity_pct'):
        return True
    if str(device.get('type', '')).lower() not in ('env', 'rpi', 'environment', 'sensor'):
        return True
    try:
        numeric = float(value)
    except (TypeError, ValueError):
        return False
    return numeric > 0


def _is_switch_port_error_event(message: str) -> bool:
    text = str(message or '')
    return (
        ('포트 ' in text and '에러 급증' in text)
        or ('in:' in text and 'out:' in text)
        or ('?ы듃 ' in text and '?먮윭' in text)
    )


@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await manager.connect(ws)
    try:
        if latest_metrics_payload:
            await ws.send_json(latest_metrics_payload)
        while True:
            data = await ws.receive_text()
            msg = json.loads(data)
            if msg.get("type") == "ping":
                await ws.send_json({"type": "pong"})
    except WebSocketDisconnect:
        manager.disconnect(ws)


@app.get("/")
async def root():
    index = FRONTEND_DIR / "index.html"
    if index.exists():
        return FileResponse(str(index))
    return {"status": "NetGuard API running", "docs": "/api/docs"}


@app.get("/login")
async def login_page():
    page = FRONTEND_DIR / "login.html"
    if page.exists():
        return FileResponse(str(page))
    return {"error": "login.html not found"}


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "timestamp": datetime.now().isoformat(),
        "version": "1.0.0"
    }
