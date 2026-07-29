"""
NetGuard Agent API — SNMP 불가 환경에서 에이전트가 직접 메트릭을 전송하는 엔드포인트
"""
import base64
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel, Field

from database import get_db_pool

logger = logging.getLogger("netguard.agent")

AGENT_API_KEY = "netguard-agent-key-2026"   # agent_config.json 과 일치
AGENT_LIVE_RESULTS: Dict[str, dict] = {}

router = APIRouter(prefix="/api/agent", tags=["agent"])

# ── 임계값 기본값 (thresholds 테이블 미등록 시 사용) ────────────────────────────
DEFAULT_THRESHOLDS = {
    "cpu_pct":      {"warn": 80.0, "crit": 95.0, "category": "performance"},
    "mem_pct":      {"warn": 75.0, "crit": 90.0, "category": "performance"},
    "disk_max_pct": {"warn": 80.0, "crit": 90.0, "category": "storage"},
}


# ── 요청 모델 ──────────────────────────────────────────────────────────────────
class RegisterRequest(BaseModel):
    hostname:    str
    ip_address:  str
    device_type: str = "server"
    location:    str = ""
    os:          str = ""


class MetricsRequest(BaseModel):
    hostname:     str
    ip_address:   str
    cpu_pct:      float = 0.0
    mem_pct:      float = 0.0
    disk_max_pct: float = 0.0
    net_in_bps:   float = 0.0
    net_out_bps:  float = 0.0
    disks:        List[Dict[str, Any]] = Field(default_factory=list)
    processes:    List[Dict[str, Any]] = Field(default_factory=list)


class SecurityReportRequest(BaseModel):
    hostname:       str
    ip_address:     str
    filename:       str
    content_base64: str
    run_type:       str = "security"
    os_type:        str = ""


def get_agent_live_results() -> List[dict]:
    return list(AGENT_LIVE_RESULTS.values())


def get_agent_live_ips() -> set:
    return set(AGENT_LIVE_RESULTS.keys())


# ── 인증 ───────────────────────────────────────────────────────────────────────
def _verify(key: Optional[str]):
    if key != AGENT_API_KEY:
        raise HTTPException(status_code=403, detail="Invalid agent key")


# ── 장치 조회 또는 생성 ────────────────────────────────────────────────────────
def _limit_text(value: Optional[str], max_len: int) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    return text[:max_len]


async def _unique_device_name(conn, desired: str, device_id: int, ip_address: str) -> str:
    name = _limit_text(desired, 100) or ip_address
    existing = await conn.fetchval(
        "SELECT id FROM devices WHERE name=$1 AND id<>$2 LIMIT 1",
        name, device_id,
    )
    if not existing:
        return name

    suffix = f" ({ip_address})"
    base = name[: max(1, 100 - len(suffix))]
    candidate = base + suffix
    counter = 2
    while await conn.fetchval(
        "SELECT id FROM devices WHERE name=$1 AND id<>$2 LIMIT 1",
        candidate, device_id,
    ):
        suffix = f" ({ip_address}-{counter})"
        base = name[: max(1, 100 - len(suffix))]
        candidate = base + suffix
        counter += 1
    logger.warning(
        "[AGENT] Device name duplicated; using '%s' instead of '%s'",
        candidate,
        name,
    )
    return candidate


async def _upsert_device(conn, req: RegisterRequest) -> int:
    hostname = _limit_text(req.hostname, 100) or req.ip_address
    device_type = _limit_text(req.device_type, 20) or "server"
    os_version = _limit_text(req.os, 200)
    location = _limit_text(req.location, 200)
    row = await conn.fetchrow(
        "SELECT id FROM devices WHERE ip_address = $1::inet", req.ip_address
    )
    if row:
        hostname = await _unique_device_name(conn, hostname, row["id"], req.ip_address)
        await conn.execute(
            """UPDATE devices
               SET name=$1, type=$2, snmp_version='agent', os_version=$3,
                   location=$4, enabled=TRUE, updated_at=NOW()
               WHERE id=$5""",
            hostname, device_type, os_version, location, row["id"],
        )
        return row["id"]
    else:
        row = await conn.fetchrow("SELECT id FROM devices WHERE name=$1 LIMIT 1", hostname)
        if row:
            await conn.execute(
                """UPDATE devices
                   SET ip_address=$1::inet, type=$2, snmp_version='agent',
                       os_version=$3, location=$4, enabled=TRUE, updated_at=NOW()
                   WHERE id=$5""",
                req.ip_address, device_type, os_version, location, row["id"],
            )
            return row["id"]
        device_id = await conn.fetchval(
            """INSERT INTO devices
                   (name, type, ip_address, snmp_version, os_version, location, enabled)
               VALUES ($1, $2, $3::inet, 'agent', $4, $5, TRUE)
               RETURNING id""",
            hostname, device_type, req.ip_address,
            os_version, location,
        )
        hostname = await _unique_device_name(conn, hostname, device_id, req.ip_address)
        await conn.execute("UPDATE devices SET name=$1 WHERE id=$2", hostname, device_id)
        return device_id


# ── 임계값 조회 ────────────────────────────────────────────────────────────────
async def _get_thresholds(conn, device_id: int) -> dict:
    rows = await conn.fetch(
        "SELECT metric_name, warn_value, crit_value FROM thresholds WHERE device_id=$1",
        device_id,
    )
    result = dict(DEFAULT_THRESHOLDS)
    for r in rows:
        if r["metric_name"] in result:
            result[r["metric_name"]]["warn"] = r["warn_value"]
            result[r["metric_name"]]["crit"] = r["crit_value"]
    return result


# ── 이벤트 생성 ────────────────────────────────────────────────────────────────
async def _check_and_create_event(conn, device_id: int, metric: str,
                                   value: float, thresholds: dict, now: datetime):
    thr = thresholds.get(metric)
    if not thr:
        return

    if value >= thr["crit"]:
        severity = "critical"
        msg = f"{metric.replace('_pct','').upper()} {value}% — 임계값 초과 ({thr['crit']}%)"
    elif value >= thr["warn"]:
        severity = "warning"
        msg = f"{metric.replace('_pct','').upper()} {value}% — 경고 임계값 ({thr['warn']}%)"
    else:
        return

    # 같은 device_id + metric + active 이벤트가 이미 있으면 중복 생성 안 함
    existing = await conn.fetchval(
        """SELECT id FROM events
           WHERE device_id=$1 AND category=$2
             AND status='active' AND time > NOW() - INTERVAL '10 minutes'
           LIMIT 1""",
        device_id, thr["category"],
    )
    if existing:
        return

    await conn.execute(
        """INSERT INTO events (time, device_id, severity, category, message, status)
           VALUES ($1, $2, $3, $4, $5, 'active')""",
        now, device_id, severity, thr["category"], msg,
    )
    logger.warning(f"[AGENT] Event created: device={device_id} {severity} {msg}")


# ── /api/agent/register ────────────────────────────────────────────────────────
@router.post("/register", summary="에이전트 장치 등록")
async def register(req: RegisterRequest, x_agent_key: Optional[str] = Header(None)):
    _verify(x_agent_key)
    pool = await get_db_pool()
    async with pool.acquire() as conn:
        device_id = await _upsert_device(conn, req)
    logger.info(f"[AGENT] Registered: {req.hostname} ({req.ip_address}) id={device_id}")
    return {"status": "ok", "device_id": device_id}


# ── /api/agent/metrics ─────────────────────────────────────────────────────────
@router.post("/metrics", summary="에이전트 메트릭 수신")
async def receive_metrics(req: MetricsRequest, x_agent_key: Optional[str] = Header(None)):
    _verify(x_agent_key)
    pool = await get_db_pool()
    now  = datetime.now(timezone.utc)

    async with pool.acquire() as conn:
        # 장치 조회 (없으면 자동 생성)
        row = await conn.fetchrow(
            "SELECT id FROM devices WHERE ip_address = $1::inet", req.ip_address
        )
        if not row:
            device_id = await _upsert_device(
                conn,
                RegisterRequest(
                    hostname=req.hostname, ip_address=req.ip_address
                ),
            )
            logger.info(f"[AGENT] Auto-registered: {req.hostname} ({req.ip_address})")
        else:
            device_id = row["id"]
            hostname = await _unique_device_name(conn, req.hostname, device_id, req.ip_address)
            await conn.execute(
                """UPDATE devices
                   SET name=$1, type='server', snmp_version='agent',
                       enabled=TRUE, updated_at=NOW()
                   WHERE id=$2""",
                hostname, device_id,
            )

        # 메트릭 저장 — 기존 SNMP 저장 방식과 동일한 테이블/컬럼명
        metric_rows = [
            (now, device_id, "cpu_pct",      req.cpu_pct),
            (now, device_id, "mem_pct",      req.mem_pct),
            (now, device_id, "disk_max_pct", req.disk_max_pct),
            (now, device_id, "net_in_bps",   req.net_in_bps),
            (now, device_id, "net_out_bps",  req.net_out_bps),
        ]
        await conn.executemany(
            "INSERT INTO metrics (time, device_id, metric_name, value) VALUES ($1,$2,$3,$4)",
            metric_rows,
        )

        # last_seen 갱신
        await conn.execute(
            "UPDATE devices SET updated_at=$1 WHERE id=$2", now, device_id
        )

        # 임계값 초과 이벤트 생성
        thresholds = await _get_thresholds(conn, device_id)
        for metric in ("cpu_pct", "mem_pct", "disk_max_pct"):
            await _check_and_create_event(
                conn, device_id, metric,
                getattr(req, metric), thresholds, now,
            )

    AGENT_LIVE_RESULTS[req.ip_address] = {
        "device_id": device_id,
        "device": hostname if 'hostname' in locals() else req.hostname,
        "ip": req.ip_address,
        "type": "server",
        "status": "online",
        "timestamp": now.isoformat(),
        "metrics": {
            "cpu_pct": round(req.cpu_pct, 1),
            "mem_pct": round(req.mem_pct, 1),
            "disk_max_pct": round(req.disk_max_pct, 1),
            "net_in_bps": round(req.net_in_bps, 1),
            "net_out_bps": round(req.net_out_bps, 1),
            "disks": req.disks,
            "processes": req.processes,
            "interfaces": [],
        },
    }

    logger.info(
        f"[AGENT] {req.hostname} ({req.ip_address}) "
        f"cpu={req.cpu_pct}% mem={req.mem_pct}% disk={req.disk_max_pct}%"
    )
    return {"status": "ok", "device_id": device_id}


# ── /api/agent/security-report ────────────────────────────────────────────────
@router.post("/security-report", summary="에이전트 점검/취약점 결과 업로드")
async def receive_security_report(req: SecurityReportRequest, x_agent_key: Optional[str] = Header(None)):
    _verify(x_agent_key)
    try:
        data = base64.b64decode(req.content_base64)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid base64 report content")

    from security.check_reports import save_report

    pool = await get_db_pool()
    async with pool.acquire() as conn:
        result = await save_report(conn, req.filename, data, {
            "run_type": req.run_type,
            "hostname": req.hostname,
            "ip_address": req.ip_address,
            "os_type": req.os_type,
        })
    logger.info(
        "[AGENT] Check report imported: host=%s ip=%s file=%s rows=%s",
        req.hostname,
        req.ip_address,
        req.filename,
        result.get("imported_results"),
    )
    return {"status": "ok", **result}


# ── /api/agent/devices ─────────────────────────────────────────────────────────
@router.get("/devices", summary="에이전트 장치 목록")
async def list_agent_devices(x_agent_key: Optional[str] = Header(None)):
    _verify(x_agent_key)
    pool = await get_db_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """SELECT id, name, type, ip_address::text, os_version, location,
                      updated_at
               FROM devices
               WHERE snmp_version = 'agent'
               ORDER BY name"""
        )
    return [dict(r) for r in rows]
