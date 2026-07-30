"""
REST API routes for NetGuard dashboard.
"""
import base64
import logging
import os
import socket
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from pathlib import Path
import smtplib
from typing import Any, Dict, List, Optional

import yaml
from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import FileResponse
from pydantic import BaseModel

router = APIRouter()
logger = logging.getLogger("netguard.api")


# ===== MODELS =====
class DeviceCreate(BaseModel):
    name: str
    type: str
    ip_address: str
    snmp_version: str = "v2c"
    community: str = "public"
    snmp_v3_user: Optional[str] = None
    snmp_v3_auth: Optional[str] = None
    snmp_v3_priv: Optional[str] = None
    snmp_v3_security_level: Optional[str] = "authPriv"
    snmp_v3_auth_protocol: Optional[str] = "SHA"
    snmp_v3_priv_protocol: Optional[str] = "AES"
    os_version: Optional[str] = None
    location: Optional[str] = None

class DeviceUpdate(BaseModel):
    name: Optional[str] = None
    type: Optional[str] = None
    ip_address: Optional[str] = None
    snmp_version: Optional[str] = None
    community: Optional[str] = None
    snmp_v3_user: Optional[str] = None
    snmp_v3_auth: Optional[str] = None
    snmp_v3_priv: Optional[str] = None
    snmp_v3_security_level: Optional[str] = None
    snmp_v3_auth_protocol: Optional[str] = None
    snmp_v3_priv_protocol: Optional[str] = None
    os_version: Optional[str] = None
    location: Optional[str] = None

class ThresholdUpdate(BaseModel):
    device_id: Optional[int] = None
    metric_name: str
    warn_value: Optional[float] = None
    crit_value: Optional[float] = None
    direction: str = "above"

class AlertConfigUpdate(BaseModel):
    smtp_host: Optional[str] = None
    smtp_port: Optional[int] = None
    smtp_user: Optional[str] = None
    smtp_password: Optional[str] = None
    smtp_from: Optional[str] = None
    smtp_starttls: Optional[bool] = None
    alert_emails: Optional[List[str]] = None
    kakao_enabled: Optional[bool] = None
    kakao_rest_key: Optional[str] = None
    kakao_channel_token: Optional[str] = None

class AlertTestEmail(BaseModel):
    recipient: Optional[str] = None

class EventAck(BaseModel):
    event_id: int
    action: str  # acknowledge / resolve
    comment: Optional[str] = None


class CheckReportImport(BaseModel):
    filename: str
    content_base64: str
    run_type: Optional[str] = None
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    os_type: Optional[str] = None


GLOBAL_THRESHOLD_FIELDS = {
    "cpu_pct": ("CPU_WARN", "CPU_CRIT", "above"),
    "mem_pct": ("MEM_WARN", "MEM_CRIT", "above"),
    "disk_max_pct": ("DISK_WARN", "DISK_CRIT", "above"),
    "temp_c": ("TEMP_WARN", "TEMP_CRIT", "above"),
    "humidity_pct": ("HUMI_WARN_HIGH", None, "above"),
    "battery_pct": ("UPS_BATT_WARN", "UPS_BATT_CRIT", "below"),
}

ALERT_CONFIG_FIELDS = {
    "smtp_host": "SMTP_HOST",
    "smtp_port": "SMTP_PORT",
    "smtp_user": "SMTP_USER",
    "smtp_password": "SMTP_PASSWORD",
    "smtp_from": "SMTP_FROM",
    "smtp_starttls": "SMTP_STARTTLS",
    "alert_emails": "ALERT_EMAILS",
    "kakao_enabled": "KAKAO_ENABLED",
    "kakao_rest_key": "KAKAO_REST_KEY",
    "kakao_channel_token": "KAKAO_CHANNEL_TOKEN",
}


def _config_yaml_path() -> Path:
    return Path(__file__).resolve().parents[2] / "config" / "config.yaml"


def _normalize_alert_payload(payload: AlertConfigUpdate) -> dict:
    data = payload.dict(exclude_unset=True)
    if "smtp_host" in data and data["smtp_host"] is not None:
        data["smtp_host"] = data["smtp_host"].strip()
    if "smtp_user" in data and data["smtp_user"] is not None:
        data["smtp_user"] = data["smtp_user"].strip()
    if "smtp_password" in data and data["smtp_password"] is not None:
        data["smtp_password"] = data["smtp_password"].strip()
    if "smtp_from" in data and data["smtp_from"] is not None:
        data["smtp_from"] = data["smtp_from"].strip()
    if "smtp_port" in data and data["smtp_port"] is not None:
        data["smtp_port"] = int(data["smtp_port"])
    if "alert_emails" in data and data["alert_emails"] is not None:
        emails = []
        for item in data["alert_emails"]:
            for part in str(item).replace(";", ",").split(","):
                part = part.strip()
                if part:
                    emails.append(part)
        data["alert_emails"] = emails
    return data


def _apply_alert_runtime_settings(data: dict):
    from config import settings

    for yaml_key, attr in ALERT_CONFIG_FIELDS.items():
        if yaml_key in data:
            setattr(settings, attr, data[yaml_key])


def _read_config_yaml() -> dict:
    path = _config_yaml_path()
    if not path.exists():
        return {}
    with open(path, encoding="utf-8-sig") as f:
        return yaml.safe_load(f) or {}


def _write_config_yaml(data: dict):
    path = _config_yaml_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        yaml.safe_dump(data, f, allow_unicode=True, sort_keys=False)


def _smtp_send_test(settings, recipient: str):
    msg = MIMEText("NetGuard SMTP test mail", "plain", "utf-8")
    msg["Subject"] = "[NetGuard] SMTP Test"
    msg["From"] = settings.SMTP_FROM
    msg["To"] = recipient
    timeout = int(getattr(settings, "SMTP_TIMEOUT", 30) or 30)
    smtp_cls = smtplib.SMTP_SSL if int(settings.SMTP_PORT) == 465 else smtplib.SMTP
    with smtp_cls(settings.SMTP_HOST, settings.SMTP_PORT, timeout=timeout) as smtp:
        if int(settings.SMTP_PORT) != 465 and getattr(settings, "SMTP_STARTTLS", False):
            smtp.starttls()
            smtp.ehlo()
        if settings.SMTP_USER:
            if int(settings.SMTP_PORT) != 465:
                if not getattr(settings, "SMTP_STARTTLS", False):
                    smtp.starttls()
                    smtp.ehlo()
            smtp.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
        smtp.send_message(msg)


def _describe_smtp_error(exc: Exception, host: str, port: int) -> str:
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
    return f"SMTP test email failed: {exc}"


async def _ensure_device_schema(conn):
    """Keep upgraded device columns available even when DB init did not run yet."""
    for ddl in [
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS snmp_v3_security_level VARCHAR(20) DEFAULT 'authPriv'",
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS snmp_v3_auth_protocol VARCHAR(20) DEFAULT 'SHA'",
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS snmp_v3_priv_protocol VARCHAR(20) DEFAULT 'AES'",
    ]:
        await conn.execute(ddl)


def _current_user(request: Request) -> dict:
    user = getattr(request.state, "user", None)
    if not user:
        raise HTTPException(401, "Authentication required")
    return user


def _require_admin(request: Request) -> dict:
    user = _current_user(request)
    if user.get("role") != "admin":
        raise HTTPException(403, "Admin permission required")
    return user


# ===== DEVICES =====
@router.get("/devices", summary="List all devices")
async def list_devices():
    from database import get_db_pool
    pool = await get_db_pool()
    async with pool.acquire() as conn:
        await _ensure_device_schema(conn)
        rows = await conn.fetch("SELECT * FROM devices WHERE enabled = TRUE ORDER BY name")
    return [dict(r) for r in rows]


@router.post("/switches/{device_id}/error-counters/reset", summary="Reset NetGuard switch error counter baseline")
async def reset_switch_error_counters(device_id: int, request: Request):
    _require_admin(request)
    from app import latest_metrics_payload
    from database import get_db_pool

    live_devices = (latest_metrics_payload or {}).get("devices", [])
    live = next((d for d in live_devices if int(d.get("device_id") or 0) == device_id), None)
    if not live:
        raise HTTPException(404, "No live switch metrics found. Wait for the next SNMP poll.")
    if live.get("type") != "switch":
        raise HTTPException(400, "Device is not a switch")

    interfaces = live.get("metrics", {}).get("interfaces", [])
    if not interfaces:
        raise HTTPException(404, "No switch interface metrics found")

    rows = []
    for iface in interfaces:
        if iface.get("index") is None:
            continue
        rows.append((
            device_id,
            int(iface.get("index")),
            str(iface.get("name") or iface.get("if_name") or iface.get("descr") or f"if{iface.get('index')}")[:200],
            int(iface.get("raw_in_errors", iface.get("in_errors", 0)) or 0),
            int(iface.get("raw_out_errors", iface.get("out_errors", 0)) or 0),
        ))

    pool = await get_db_pool()
    async with pool.acquire() as conn:
        await conn.executemany("""
            INSERT INTO switch_error_baselines
                (device_id, if_index, port_name, in_baseline, out_baseline, updated_at)
            VALUES ($1, $2, $3, $4, $5, NOW())
            ON CONFLICT (device_id, if_index)
            DO UPDATE SET
                port_name = EXCLUDED.port_name,
                in_baseline = EXCLUDED.in_baseline,
                out_baseline = EXCLUDED.out_baseline,
                updated_at = NOW()
        """, rows)
        await conn.execute("""
            UPDATE events
            SET status = 'resolved', resolved_at = NOW()
            WHERE device_id = $1
              AND status IN ('active', 'acknowledged')
              AND message LIKE '%in:%'
              AND message LIKE '%out:%'
        """, device_id)

    return {"status": "ok", "device_id": device_id, "ports": len(rows)}


@router.post("/devices", summary="Add a new device")
async def add_device(device: DeviceCreate, request: Request):
    _require_admin(request)
    from database import get_db_pool
    pool = await get_db_pool()
    async with pool.acquire() as conn:
        await _ensure_device_schema(conn)
        existing = await conn.fetchrow(
            "SELECT id, enabled FROM devices WHERE name = $1 LIMIT 1",
            device.name,
        )
        if existing:
            await conn.execute("""
                UPDATE devices
                SET type=$1,
                    ip_address=$2,
                    snmp_version=$3,
                    community=$4,
                    snmp_v3_user=$5,
                    snmp_v3_auth=$6,
                    snmp_v3_priv=$7,
                    snmp_v3_security_level=$8,
                    snmp_v3_auth_protocol=$9,
                    snmp_v3_priv_protocol=$10,
                    os_version=$11,
                    location=$12,
                    enabled=TRUE,
                    updated_at=NOW()
                WHERE id=$13
            """, device.type, device.ip_address, device.snmp_version,
                 device.community, device.snmp_v3_user, device.snmp_v3_auth,
                 device.snmp_v3_priv, device.snmp_v3_security_level,
                 device.snmp_v3_auth_protocol, device.snmp_v3_priv_protocol,
                 device.os_version, device.location, existing["id"])
            return {
                "id": existing["id"],
                "status": "restored" if existing["enabled"] is False else "updated",
            }
        try:
            row = await conn.fetchrow("""
                INSERT INTO devices (name, type, ip_address, snmp_version, community,
                                     snmp_v3_user, snmp_v3_auth, snmp_v3_priv,
                                     snmp_v3_security_level, snmp_v3_auth_protocol,
                                     snmp_v3_priv_protocol, os_version, location)
                VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) RETURNING id
            """, device.name, device.type, device.ip_address, device.snmp_version,
                 device.community, device.snmp_v3_user, device.snmp_v3_auth,
                 device.snmp_v3_priv, device.snmp_v3_security_level,
                 device.snmp_v3_auth_protocol, device.snmp_v3_priv_protocol,
                 device.os_version, device.location)
        except Exception as e:
            logger.error("Device create failed: %s", e, exc_info=True)
            raise HTTPException(status_code=400, detail=f"Device create failed: {e}")
    return {"id": row["id"], "status": "created"}


@router.put("/devices/{device_id}", summary="Update a device")
async def update_device(device_id: int, device: DeviceUpdate, request: Request):
    _require_admin(request)
    from database import get_db_pool
    pool = await get_db_pool()
    updates = {k: v for k, v in device.dict().items() if v is not None}
    if not updates:
        return {"status": "no changes"}
    set_clause = ", ".join(f"{k} = ${i+2}" for i, k in enumerate(updates))
    params = [device_id] + list(updates.values())
    async with pool.acquire() as conn:
        await _ensure_device_schema(conn)
        try:
            result = await conn.execute(
                f"UPDATE devices SET {set_clause}, updated_at = NOW() WHERE id = $1",
                *params,
            )
        except Exception as e:
            logger.error("Device update failed id=%s: %s", device_id, e, exc_info=True)
            raise HTTPException(status_code=400, detail=f"Device update failed: {e}")
    if result == "UPDATE 0":
        raise HTTPException(status_code=404, detail=f"Device {device_id} not found")
    return {"status": "updated"}


@router.delete("/devices/{device_id}", summary="Remove a device")
async def remove_device(device_id: int, request: Request):
    _require_admin(request)
    from database import get_db_pool
    pool = await get_db_pool()
    async with pool.acquire() as conn:
        await conn.execute("UPDATE devices SET enabled = FALSE WHERE id = $1", device_id)
    return {"status": "deleted"}


# ===== METRICS =====
@router.get("/metrics/{device_id}", summary="Get recent metrics for a device")
async def get_metrics(
    device_id: int,
    metric: str = Query("cpu_pct"),
    hours: int = Query(6, ge=1, le=168)
):
    from database import get_db_pool
    pool = await get_db_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch("""
            SELECT to_timestamp(floor(extract(epoch FROM time) / 300) * 300) AS bucket,
                   AVG(value) AS avg_value, MAX(value) AS max_value
            FROM metrics
            WHERE device_id = $1
              AND metric_name = $2
              AND time >= NOW() - INTERVAL '1 hour' * $3
            GROUP BY bucket ORDER BY bucket
        """, device_id, metric, hours)
    return [{"time": str(r["bucket"]), "avg": round(r["avg_value"], 2),
             "max": round(r["max_value"], 2)} for r in rows]


@router.get("/metrics/latest", summary="Latest metric snapshot for all devices")
async def latest_metrics():
    from database import get_db_pool
    pool = await get_db_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch("""
            SELECT DISTINCT ON (m.device_id, m.metric_name)
                   m.device_id, d.name AS device_name, m.metric_name, m.value, m.time
            FROM metrics m
            JOIN devices d ON d.id = m.device_id
            WHERE m.time >= NOW() - INTERVAL '24 hours'
            ORDER BY m.device_id, m.metric_name, m.time DESC
        """)
    return [dict(r) for r in rows]


# ===== EVENTS =====
@router.get("/events", summary="List events")
async def list_events(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = Query(100, le=1000),
    hours: int = Query(24)
):
    from database import get_db_pool
    pool = await get_db_pool()
    conditions = [
        "e.time >= NOW() - INTERVAL '1 hour' * $1",
        "NOT ((e.message LIKE '포트 % 에러 급증%') OR (e.message LIKE '%in:%' AND e.message LIKE '%out:%'))",
    ]
    params: list = [hours]

    if severity:
        params.append(severity)
        conditions.append(f"e.severity = ${len(params)}")
    if status:
        params.append(status)
        conditions.append(f"e.status = ${len(params)}")

    where = " AND ".join(conditions)
    params.append(limit)

    async with pool.acquire() as conn:
        rows = await conn.fetch(f"""
            SELECT e.*, d.name AS device_name
            FROM events e LEFT JOIN devices d ON d.id = e.device_id
            WHERE {where}
            ORDER BY e.time DESC LIMIT ${len(params)}
        """, *params)
    return [dict(r) for r in rows]


@router.post("/events/ack", summary="Acknowledge or resolve an event")
async def ack_event(payload: EventAck, request: Request):
    _require_admin(request)
    from database import get_db_pool
    pool = await get_db_pool()
    async with pool.acquire() as conn:
        if payload.action == "acknowledge":
            await conn.execute(
                "UPDATE events SET status='acknowledged' WHERE id=$1", payload.event_id)
        elif payload.action == "resolve":
            await conn.execute(
                "UPDATE events SET status='resolved', resolved_at=NOW() WHERE id=$1",
                payload.event_id)
    return {"status": "ok"}


@router.delete("/events/bulk", summary="Delete events in bulk")
async def delete_events_bulk(
    status: Optional[str] = Query(None, description="Filter: active | acknowledged | resolved | (omit = all)")
):
    from database import get_db_pool
    pool = await get_db_pool()
    conditions: list = []
    params: list = []
    if status and status != "all":
        params.append(status)
        conditions.append(f"status = ${len(params)}")
    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    async with pool.acquire() as conn:
        result = await conn.execute(f"DELETE FROM events {where}", *params)
    deleted = int(result.split()[-1]) if result else 0
    return {"status": "ok", "deleted": deleted}


@router.delete("/events/{event_id}", summary="Delete a single event")
async def delete_event(event_id: int):
    from database import get_db_pool
    pool = await get_db_pool()
    async with pool.acquire() as conn:
        result = await conn.execute("DELETE FROM events WHERE id = $1", event_id)
    if int(result.split()[-1]) == 0:
        raise HTTPException(404, f"Event {event_id} not found")
    return {"status": "ok"}


# ===== SECURITY =====
@router.get("/security/cves", summary="CVE summary across all devices")
async def get_cves():
    from app import cve_checker
    from database import get_db_pool
    pool = await get_db_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch("SELECT name, os_version FROM devices WHERE enabled=TRUE")
        completed_rows = await conn.fetch("SELECT cve_id FROM cve_completions")
    devices = [dict(r) for r in rows]
    completed_cve_ids = {r["cve_id"] for r in completed_rows}
    if cve_checker:
        return cve_checker.get_summary(devices, completed_cve_ids)
    return {"total": 0, "counts": {}, "items": []}


@router.get("/security/cves/{cve_id}", summary="CVE detail")
async def get_cve_detail(cve_id: str):
    from app import cve_checker
    if not cve_checker or not cve_checker._loaded:
        raise HTTPException(404, "CVE DB not loaded")
    items = [c for c in cve_checker._cve_db if c['id'] == cve_id]
    if not items:
        raise HTTPException(404, f"{cve_id} not found")
    item = items[0]
    return {
        **item,
        "cve_id": item.get("id"),
        "cvss": item.get("score"),
        "description": item.get("desc"),
    }


@router.post("/security/cves/{cve_id}/complete", summary="Mark CVE as completed")
async def complete_cve(cve_id: str, request: Request):
    _require_admin(request)
    from database import get_db_pool

    pool = await get_db_pool()
    async with pool.acquire() as conn:
        await conn.execute("""
            INSERT INTO cve_completions (cve_id)
            VALUES ($1)
            ON CONFLICT (cve_id) DO UPDATE
            SET completed_at = NOW()
        """, cve_id)
    return {"status": "ok", "cve_id": cve_id}


# ===== SCRIPT CHECK RESULTS =====
@router.get("/security/checks/summary", summary="Maintenance/security script result summary")
async def get_check_summary():
    from database import get_db_pool

    pool = await get_db_pool()
    async with pool.acquire() as conn:
        summary = await conn.fetchrow("""
            SELECT
                COUNT(DISTINCT cr.id)::int AS run_count,
                COUNT(DISTINCT r.device_id)::int AS server_count,
                COUNT(DISTINCT r.check_item_id)::int AS check_item_count,
                COUNT(r.id) FILTER (WHERE r.result_status='fail')::int AS fail_count,
                COUNT(r.id) FILTER (WHERE r.result_status='warn')::int AS warn_count,
                COUNT(r.id) FILTER (WHERE r.result_status='pass')::int AS pass_count
            FROM check_runs cr
            LEFT JOIN check_results r ON r.run_id = cr.id
        """)
        status_rows = await conn.fetch("""
            SELECT result_status, COUNT(*)::int AS count
            FROM check_results
            GROUP BY result_status
            ORDER BY result_status
        """)
        latest_runs = await conn.fetch("""
            SELECT cr.id, cr.run_type, cr.report_title, cr.source_tool, cr.status,
                   cr.completed_at, COUNT(r.id)::int AS result_count,
                   COUNT(*) FILTER (WHERE r.result_status='fail')::int AS fail_count,
                   COUNT(*) FILTER (WHERE r.result_status='warn')::int AS warn_count
            FROM check_runs cr
            LEFT JOIN check_results r ON r.run_id = cr.id
            GROUP BY cr.id
            ORDER BY cr.completed_at DESC
            LIMIT 20
        """)
        item_summary = await conn.fetch("""
            SELECT i.id, i.code, i.name, i.category, i.severity,
                   COUNT(r.id)::int AS result_count,
                   COUNT(*) FILTER (WHERE r.result_status='fail')::int AS fail_count,
                   COUNT(*) FILTER (WHERE r.result_status='warn')::int AS warn_count
            FROM check_items i
            LEFT JOIN check_results r ON r.check_item_id = i.id
            GROUP BY i.id
            ORDER BY fail_count DESC, warn_count DESC, i.category, i.code
            LIMIT 20
        """)
        server_summary = await conn.fetch("""
            SELECT d.id, d.name AS hostname, d.ip_address::text AS ip_address, d.os_version AS os_type,
                   COUNT(r.id)::int AS result_count,
                   COUNT(*) FILTER (WHERE r.result_status='fail')::int AS fail_count,
                   COUNT(*) FILTER (WHERE r.result_status='warn')::int AS warn_count,
                   MAX(r.checked_at) AS last_checked_at
            FROM devices d
            JOIN check_results r ON r.device_id = d.id
            GROUP BY d.id
            ORDER BY fail_count DESC, warn_count DESC, d.name
            LIMIT 20
        """)
    return {
        "summary": dict(summary) if summary else {},
        "status": [dict(r) for r in status_rows],
        "latest_runs": [dict(r) for r in latest_runs],
        "item_summary": [dict(r) for r in item_summary],
        "server_summary": [dict(r) for r in server_summary],
    }


@router.get("/security/checks/runs", summary="List imported script check runs")
async def list_check_runs(limit: int = Query(100, le=1000), run_type: Optional[str] = None):
    from database import get_db_pool

    conditions = []
    params: list = []
    if run_type:
        params.append(run_type)
        conditions.append(f"cr.run_type = ${len(params)}")
    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    params.append(limit)

    pool = await get_db_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(f"""
            SELECT cr.id, cr.run_type, cr.report_title, cr.source_tool, cr.status,
                   cr.completed_at, cr.notes,
                   COUNT(r.id)::int AS result_count,
                   COUNT(*) FILTER (WHERE r.result_status='fail')::int AS fail_count,
                   COUNT(*) FILTER (WHERE r.result_status='warn')::int AS warn_count,
                   rf.id AS report_file_id,
                   rf.original_name AS report_file
            FROM check_runs cr
            LEFT JOIN check_results r ON r.run_id = cr.id
            LEFT JOIN report_files rf ON rf.run_id = cr.id
            {where}
            GROUP BY cr.id, rf.id, rf.original_name
            ORDER BY cr.completed_at DESC
            LIMIT ${len(params)}
        """, *params)
    return [dict(r) for r in rows]


@router.get("/security/checks/runs/{run_id}/results", summary="List results for one check run")
async def get_check_run_results(run_id: int):
    from database import get_db_pool

    pool = await get_db_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch("""
            SELECT r.id, r.result_status, r.result_value, r.evidence, r.recommendation,
                   r.checked_at, d.name AS hostname, d.ip_address::text AS ip_address,
                   i.code, i.name AS item_name, i.category, i.severity
            FROM check_results r
            JOIN devices d ON d.id = r.device_id
            JOIN check_items i ON i.id = r.check_item_id
            WHERE r.run_id = $1
            ORDER BY r.result_status, i.category, i.code
        """, run_id)
    return [dict(r) for r in rows]


@router.post("/security/checks/reports", summary="Upload a maintenance/security script report")
async def upload_check_report(
    request: Request,
    report_file: UploadFile = File(...),
    run_type: Optional[str] = Form(None),
    hostname: Optional[str] = Form(None),
    ip_address: Optional[str] = Form(None),
    os_type: Optional[str] = Form(None),
):
    _require_admin(request)
    from database import get_db_pool
    from security.check_reports import save_report

    data = await report_file.read()
    pool = await get_db_pool()
    async with pool.acquire() as conn:
        result = await save_report(conn, report_file.filename or "report.dat", data, {
            "run_type": run_type,
            "hostname": hostname,
            "ip_address": ip_address,
            "os_type": os_type,
        })
    return {"status": "ok", **result}


@router.post("/security/checks/reports/json", summary="Upload a base64 report")
async def upload_check_report_json(payload: CheckReportImport, request: Request):
    _require_admin(request)
    from database import get_db_pool
    from security.check_reports import save_report

    try:
        data = base64.b64decode(payload.content_base64)
    except Exception:
        raise HTTPException(400, "Invalid base64 report content")
    pool = await get_db_pool()
    async with pool.acquire() as conn:
        result = await save_report(conn, payload.filename, data, payload.dict())
    return {"status": "ok", **result}


@router.get("/security/checks/files/{file_id}/download", summary="Download an imported report file")
async def download_check_report_file(file_id: int):
    from database import get_db_pool

    pool = await get_db_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow("""
            SELECT original_name, mime_type, storage_path
            FROM report_files
            WHERE id = $1
        """, file_id)
    if not row or not os.path.exists(row["storage_path"]):
        raise HTTPException(404, "Report file not found")
    return FileResponse(
        row["storage_path"],
        media_type=row["mime_type"] or "application/octet-stream",
        filename=row["original_name"],
    )


@router.delete("/security/checks/runs/{run_id}", summary="Delete an imported script check run")
async def delete_check_run(run_id: int, request: Request):
    _require_admin(request)
    from database import get_db_pool

    pool = await get_db_pool()
    async with pool.acquire() as conn:
        files = await conn.fetch("SELECT storage_path FROM report_files WHERE run_id=$1", run_id)
        result = await conn.execute("DELETE FROM check_runs WHERE id=$1", run_id)
    if int(result.split()[-1]) == 0:
        raise HTTPException(404, f"Check run {run_id} not found")
    for item in files:
        try:
            if item["storage_path"] and os.path.exists(item["storage_path"]):
                os.remove(item["storage_path"])
        except OSError:
            logger.warning("Could not delete report file %s", item["storage_path"])
    return {"status": "ok", "id": run_id}


# ===== ALERT CONFIG =====
@router.get("/alert-config", summary="Get alert notification settings")
async def get_alert_config(request: Request):
    _require_admin(request)
    from config import settings

    return {
        "smtp_host": settings.SMTP_HOST,
        "smtp_port": settings.SMTP_PORT,
        "smtp_user": settings.SMTP_USER,
        "smtp_password": settings.SMTP_PASSWORD,
        "smtp_from": settings.SMTP_FROM,
        "smtp_starttls": settings.SMTP_STARTTLS,
        "alert_emails": settings.ALERT_EMAILS,
        "kakao_enabled": settings.KAKAO_ENABLED,
        "kakao_rest_key": settings.KAKAO_REST_KEY,
        "kakao_channel_token": settings.KAKAO_CHANNEL_TOKEN,
    }


@router.post("/alert-config", summary="Update alert notification settings")
async def update_alert_config(payload: AlertConfigUpdate, request: Request):
    _require_admin(request)

    try:
        updates = _normalize_alert_payload(payload)
        if not updates:
            return {"status": "ok", "updated": []}

        # Apply runtime values first so test-send can work even if config.yaml is not writable.
        _apply_alert_runtime_settings(updates)

        config_data = _read_config_yaml()
        for key, value in updates.items():
            config_data[key] = value

        persisted = True
        warning = None
        try:
            _write_config_yaml(config_data)
        except PermissionError as e:
            persisted = False
            warning = (
                f"Runtime setting was applied, but config.yaml could not be saved: {e}. "
                "Check file ownership/permission."
            )
            logger.error("Alert config file save permission failed: %s", e)
        except OSError as e:
            persisted = False
            warning = f"Runtime setting was applied, but config.yaml could not be saved: {e}"
            logger.error("Alert config file save failed: %s", e)

        logger.info(
            "Alert config updated: %s (persisted=%s)",
            ", ".join(sorted(updates.keys())),
            persisted,
        )
        return {
            "status": "ok",
            "updated": sorted(updates.keys()),
            "persisted": persisted,
            "warning": warning,
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Alert config update failed")
        raise HTTPException(500, f"Alert config update failed: {e}")


@router.post("/alert-config/test-email", summary="Send SMTP test email")
async def test_alert_email(payload: AlertTestEmail, request: Request):
    _require_admin(request)
    from config import settings
    import asyncio

    recipient = (payload.recipient or "").strip()
    if not recipient:
        if not settings.ALERT_EMAILS:
            raise HTTPException(400, "No alert email recipient configured")
        recipient = settings.ALERT_EMAILS[0]

    if not settings.SMTP_HOST:
        raise HTTPException(400, "SMTP host is not configured")

    try:
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, _smtp_send_test, settings, recipient)
    except Exception as e:
        detail = _describe_smtp_error(e, settings.SMTP_HOST, settings.SMTP_PORT)
        logger.error("SMTP test email failed: %s", detail)
        raise HTTPException(500, detail)

    return {"status": "ok", "recipient": recipient}


# ===== THRESHOLDS =====
@router.get("/thresholds", summary="Get threshold settings")
async def get_thresholds():
    from database import get_db_pool
    pool = await get_db_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch("""
            SELECT t.*, d.name AS device_name
            FROM thresholds t LEFT JOIN devices d ON d.id = t.device_id
            ORDER BY t.metric_name
        """)
    return [dict(r) for r in rows]


@router.get("/thresholds/effective", summary="Get effective global threshold settings")
async def get_effective_thresholds():
    from config import settings
    from database import get_db_pool

    values = {
        metric_name: {
            "metric_name": metric_name,
            "warn_value": getattr(settings, warn_attr),
            "crit_value": getattr(settings, crit_attr) if crit_attr else None,
            "direction": direction,
        }
        for metric_name, (warn_attr, crit_attr, direction) in GLOBAL_THRESHOLD_FIELDS.items()
    }

    pool = await get_db_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch("""
            SELECT metric_name, warn_value, crit_value, direction
            FROM thresholds
            WHERE device_id IS NULL
              AND metric_name = ANY($1::text[])
        """, list(GLOBAL_THRESHOLD_FIELDS.keys()))

    for row in rows:
        metric_name = row["metric_name"]
        values[metric_name] = {
            "metric_name": metric_name,
            "warn_value": row["warn_value"],
            "crit_value": row["crit_value"],
            "direction": row["direction"],
        }
    return values


@router.post("/thresholds", summary="Create or update threshold")
async def upsert_threshold(payload: ThresholdUpdate, request: Request):
    _require_admin(request)
    from database import get_db_pool
    pool = await get_db_pool()
    async with pool.acquire() as conn:
        if payload.device_id is None:
            existing_id = await conn.fetchval("""
                SELECT id
                FROM thresholds
                WHERE device_id IS NULL AND metric_name = $1
                ORDER BY id
                LIMIT 1
            """, payload.metric_name)
            if existing_id:
                await conn.execute("""
                    UPDATE thresholds
                    SET warn_value=$2, crit_value=$3, direction=$4
                    WHERE id=$1
                """, existing_id, payload.warn_value, payload.crit_value, payload.direction)
            else:
                await conn.execute("""
                    INSERT INTO thresholds (device_id, metric_name, warn_value, crit_value, direction)
                    VALUES (NULL, $1, $2, $3, $4)
                """, payload.metric_name, payload.warn_value,
                     payload.crit_value, payload.direction)
        else:
            await conn.execute("""
                INSERT INTO thresholds (device_id, metric_name, warn_value, crit_value, direction)
                VALUES ($1,$2,$3,$4,$5)
                ON CONFLICT (device_id, metric_name)
                DO UPDATE SET warn_value=$3, crit_value=$4, direction=$5
            """, payload.device_id, payload.metric_name,
                 payload.warn_value, payload.crit_value, payload.direction)
    return {"status": "ok"}


# ===== DASHBOARD SUMMARY =====
@router.get("/dashboard/summary", summary="Overall status summary")
async def dashboard_summary():
    from database import get_db_pool
    pool = await get_db_pool()
    async with pool.acquire() as conn:
        device_count = await conn.fetchval("SELECT COUNT(*) FROM devices WHERE enabled=TRUE")
        active_events = await conn.fetchval(
            """
            SELECT COUNT(*)
            FROM events
            WHERE status='active'
              AND time >= NOW() - INTERVAL '1 hour'
              AND NOT ((message LIKE '포트 % 에러 급증%') OR (message LIKE '%in:%' AND message LIKE '%out:%'))
            """)
        critical_events = await conn.fetchval(
            """
            SELECT COUNT(*)
            FROM events
            WHERE status='active'
              AND severity='critical'
              AND time >= NOW() - INTERVAL '1 hour'
              AND NOT ((message LIKE '포트 % 에러 급증%') OR (message LIKE '%in:%' AND message LIKE '%out:%'))
            """)
    return {
        "devices": device_count,
        "active_events": active_events,
        "critical_events": critical_events,
        "timestamp": datetime.now().isoformat()
    }
