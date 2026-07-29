"""
Server maintenance and security check report import helpers.

The report scripts in agent/check_scripts emit CSV/HTML, and the Windows
security script may also emit XLSX.  This module normalizes those files into
NetGuard devices, check runs, check items, and check results.
"""
from __future__ import annotations

import csv
import html
import json
import logging
import re
import uuid
import zipfile
from io import BytesIO, StringIO
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional
from xml.etree import ElementTree as ET

logger = logging.getLogger("netguard.check_reports")

REPORT_STORAGE_DIR = Path(__file__).resolve().parent.parent / "data" / "security_reports"
VALID_RUN_TYPES = {"maintenance", "security", "combined"}


def _decode_bytes(data: bytes) -> str:
    for encoding in ("utf-8-sig", "utf-8", "cp949", "euc-kr"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


def _clean_text(value: Any) -> str:
    text = html.unescape(str(value or ""))
    text = re.sub(r"<br\s*/?>", " | ", text, flags=re.I)
    text = re.sub(r"<[^>]+>", "", text)
    return re.sub(r"\s+", " ", text).strip()


def _normalize_status(value: str) -> str:
    status = _clean_text(value).lower()
    if status in {"정상", "양호", "pass", "ok", "good"}:
        return "pass"
    if status in {"취약", "실패", "위험", "fail", "bad", "critical"}:
        return "fail"
    if status in {"주의", "확인필요", "경고", "warn", "warning", "review"}:
        return "warn"
    return "na"


def _normalize_severity(value: str, fallback_status: str) -> str:
    severity = _clean_text(value).lower()
    if severity in {"상", "높음", "critical", "high", "h"}:
        return "high"
    if severity in {"중", "보통", "medium", "m"}:
        return "medium"
    if severity in {"하", "낮음", "low", "l"}:
        return "low"
    return "high" if fallback_status == "fail" else "medium"


def _first(row: Dict[str, str], *keys: str) -> str:
    for key in keys:
        if row.get(key):
            return row[key]
    return ""


def _extract_info(text: str, label: str) -> str:
    patterns = [
        rf"<label>\s*{re.escape(label)}\s*</label>\s*<span>([\s\S]*?)</span>",
        rf"<th[^>]*>\s*{re.escape(label)}\s*</th>\s*<td[^>]*>([\s\S]*?)</td>",
        rf"{re.escape(label)}\s*[:：]\s*([^\n\r<]+)",
    ]
    for pattern in patterns:
        match = re.search(pattern, text, flags=re.I)
        if match:
            return _clean_text(match.group(1))
    return ""


def infer_report_info(filename: str, requested_type: str = "", text: str = "") -> Dict[str, str]:
    lower_name = filename.lower()
    security = (
        "cve" in lower_name
        or "security" in lower_name
        or "보안 취약점" in text
        or "위험도" in text
    )
    run_type = requested_type if requested_type in VALID_RUN_TYPES else ("security" if security else "maintenance")
    match = re.search(r"(?:CVE_Check_)?(.+?)_((?:\d{1,3}\.){3}\d{1,3})_(\d{8})", filename, flags=re.I)
    hostname = _extract_info(text, "서버명") or (match.group(1) if match else Path(filename).stem)
    ip_address = _extract_info(text, "IP 주소") or (match.group(2) if match else "")
    return {
        "hostname": hostname,
        "ip_address": ip_address,
        "os_type": _extract_info(text, "운영체제"),
        "report_date": match.group(3) if match else (_extract_info(text, "점검 일시") or _extract_info(text, "진단 일시")),
        "run_type": run_type,
        "source_tool": "Server Security Check" if security else "Server Maintenance",
    }


def _parse_csv(text: str) -> List[Dict[str, str]]:
    reader = csv.DictReader(StringIO(text))
    return [{str(k or "").strip(): _clean_text(v) for k, v in row.items()} for row in reader]


def _parse_html(text: str) -> List[Dict[str, str]]:
    table_matches = re.findall(r"<table[\s\S]*?</table>", text, flags=re.I)
    target = next((t for t in table_matches if "항목ID" in t and ("점검항목" in t or "점검 항목" in t)), "")
    if not target:
        return []
    header_match = re.search(r"<thead>[\s\S]*?<tr>([\s\S]*?)</tr>[\s\S]*?</thead>", target, flags=re.I)
    headers = re.findall(r"<th[^>]*>([\s\S]*?)</th>", header_match.group(1), flags=re.I) if header_match else []
    headers = [_clean_text(h) for h in headers]
    if not headers:
        return []
    body_match = re.search(r"<tbody[^>]*>([\s\S]*?)</tbody>", target, flags=re.I)
    body = body_match.group(1) if body_match else target
    rows = []
    for row_html in re.findall(r"<tr[^>]*>([\s\S]*?)</tr>", body, flags=re.I):
        cells = [_clean_text(c) for c in re.findall(r"<td[^>]*>([\s\S]*?)</td>", row_html, flags=re.I)]
        if cells:
            rows.append({headers[i]: cells[i] if i < len(cells) else "" for i in range(len(headers))})
    return rows


def _xlsx_shared_strings(zf: zipfile.ZipFile) -> List[str]:
    try:
        root = ET.fromstring(zf.read("xl/sharedStrings.xml"))
    except KeyError:
        return []
    ns = {"x": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
    values = []
    for si in root.findall("x:si", ns):
        texts = [node.text or "" for node in si.findall(".//x:t", ns)]
        values.append("".join(texts))
    return values


def _cell_col(cell_ref: str) -> int:
    letters = re.sub(r"[^A-Z]", "", cell_ref.upper())
    total = 0
    for ch in letters:
        total = total * 26 + (ord(ch) - ord("A") + 1)
    return max(0, total - 1)


def _parse_xlsx(data: bytes) -> List[Dict[str, str]]:
    with zipfile.ZipFile(BytesIO(data)) as zf:
        shared = _xlsx_shared_strings(zf)
        sheets = [name for name in zf.namelist() if re.match(r"xl/worksheets/sheet\d+\.xml$", name)]
        if not sheets:
            return []
    ns = {"x": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
    matrices: List[List[List[str]]] = []
    with zipfile.ZipFile(BytesIO(data)) as zf:
        for sheet in sheets:
            root = ET.fromstring(zf.read(sheet))
            matrix: List[List[str]] = []
            for row in root.findall(".//x:sheetData/x:row", ns):
                values: Dict[int, str] = {}
                for cell in row.findall("x:c", ns):
                    ref = cell.attrib.get("r", "A1")
                    col = _cell_col(ref)
                    cell_type = cell.attrib.get("t")
                    value_node = cell.find("x:v", ns)
                    inline_node = cell.find("x:is/x:t", ns)
                    raw = inline_node.text if inline_node is not None else (value_node.text if value_node is not None else "")
                    if cell_type == "s" and raw.isdigit():
                        raw = shared[int(raw)] if int(raw) < len(shared) else ""
                    values[col] = _clean_text(raw)
                if values:
                    width = max(values) + 1
                    matrix.append([values.get(i, "") for i in range(width)])
            if matrix:
                matrices.append(matrix)

    matrix = next(
        (m for m in matrices if m and any("항목ID" in cell for cell in m[0])),
        matrices[0] if matrices else [],
    )
    if not matrix:
        return []
    header_index = next(
        (idx for idx, row in enumerate(matrix) if any("항목ID" in cell for cell in row)),
        0,
    )
    headers = matrix[header_index]
    return [
        {headers[i]: row[i] if i < len(row) else "" for i in range(len(headers))}
        for row in matrix[header_index + 1:]
    ]


def parse_report(filename: str, data: bytes, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    options = options or {}
    suffix = Path(filename).suffix.lower()
    text = "" if suffix == ".xlsx" else _decode_bytes(data)
    info = infer_report_info(filename, str(options.get("run_type") or ""), text)
    rows = []
    if suffix == ".csv":
        rows = _parse_csv(text)
    elif suffix in {".html", ".htm"}:
        rows = _parse_html(text)
    elif suffix == ".xlsx":
        rows = _parse_xlsx(data)

    normalized = []
    for row in rows:
        raw_status = _first(row, "점검결과", "점검 결과", "결과", "Result", "Status")
        status = _normalize_status(raw_status)
        code = _first(row, "항목ID", "코드", "ID", "Code")
        name = _first(row, "점검항목", "점검 항목", "항목명", "Name") or code
        if not code or not name:
            continue
        normalized.append({
            "hostname": options.get("hostname") or info["hostname"],
            "ip_address": options.get("ip_address") or info["ip_address"],
            "os_type": options.get("os_type") or info["os_type"],
            "code": f"{info['run_type'].upper()}-{code}",
            "name": name,
            "category": _first(row, "분류", "Category") or "General",
            "severity": _normalize_severity(_first(row, "위험도", "Severity"), status),
            "status": status,
            "value": _first(row, "상세내용", "상세 내용", "Value", "Detail"),
            "evidence": _first(row, "판단기준", "판단 기준", "Evidence"),
            "recommendation": _first(row, "조치권고사항", "조치 권고사항", "Recommendation"),
            "description": _first(row, "판단기준", "판단 기준", "Description"),
        })
    return {"info": info, "rows": normalized}


def _safe_filename(filename: str) -> str:
    safe = re.sub(r"[^a-zA-Z0-9._가-힣-]+", "_", Path(filename).name).strip("._")
    return safe or "report.dat"


async def _upsert_device(conn, item: Dict[str, Any]) -> int:
    hostname = (item.get("hostname") or item.get("ip_address") or "unknown-server")[:100]
    ip_address = item.get("ip_address") or None
    os_type = (item.get("os_type") or "")[:200] or None
    if ip_address:
        row = await conn.fetchrow("SELECT id FROM devices WHERE ip_address = $1::inet LIMIT 1", ip_address)
        if row:
            name_exists = await conn.fetchval(
                "SELECT id FROM devices WHERE name=$1 AND id<>$2 LIMIT 1",
                hostname,
                row["id"],
            )
            device_name = hostname if not name_exists else await conn.fetchval(
                "SELECT name FROM devices WHERE id=$1",
                row["id"],
            )
            await conn.execute(
                "UPDATE devices SET name=$1, type='server', os_version=COALESCE($2, os_version), enabled=TRUE, updated_at=NOW() WHERE id=$3",
                device_name, os_type, row["id"],
            )
            return row["id"]
    row = await conn.fetchrow("SELECT id FROM devices WHERE name=$1 LIMIT 1", hostname)
    if row:
        await conn.execute(
            "UPDATE devices SET type='server', os_version=COALESCE($1, os_version), enabled=TRUE, updated_at=NOW() WHERE id=$2",
            os_type, row["id"],
        )
        return row["id"]
    return await conn.fetchval(
        """
        INSERT INTO devices (name, type, ip_address, snmp_version, os_version, enabled)
        VALUES ($1, 'server', NULLIF($2, '')::inet, 'agent', $3, TRUE)
        RETURNING id
        """,
        hostname, ip_address or "", os_type,
    )


async def save_report(conn, filename: str, data: bytes, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    parsed = parse_report(filename, data, options)
    info = parsed["info"]
    rows = parsed["rows"]
    run_type = info["run_type"] if info["run_type"] in VALID_RUN_TYPES else "combined"

    REPORT_STORAGE_DIR.mkdir(parents=True, exist_ok=True)
    stored_name = f"{uuid.uuid4().hex}_{_safe_filename(filename)}"
    storage_path = REPORT_STORAGE_DIR / stored_name
    storage_path.write_bytes(data)

    run_id = await conn.fetchval(
        """
        INSERT INTO check_runs (run_type, source_tool, report_title, status, notes)
        VALUES ($1, $2, $3, 'completed', $4)
        RETURNING id
        """,
        run_type,
        info.get("source_tool") or "agent-report",
        filename,
        json.dumps({"report_date": info.get("report_date")}, ensure_ascii=False),
    )
    await conn.execute(
        """
        INSERT INTO report_files (run_id, original_name, stored_name, mime_type, size_bytes, storage_path)
        VALUES ($1, $2, $3, $4, $5, $6)
        """,
        run_id,
        filename,
        stored_name,
        _mime_type(filename),
        len(data),
        str(storage_path),
    )

    for item in rows:
        device_id = await _upsert_device(conn, item)
        check_item_id = await conn.fetchval(
            """
            INSERT INTO check_items (code, name, category, severity, description)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (code) DO UPDATE SET
                name=EXCLUDED.name,
                category=EXCLUDED.category,
                severity=EXCLUDED.severity,
                description=EXCLUDED.description
            RETURNING id
            """,
            item["code"],
            item["name"],
            item["category"],
            item["severity"],
            item.get("description"),
        )
        await conn.execute(
            """
            INSERT INTO check_results (
                run_id, device_id, check_item_id, result_status, result_value, evidence, recommendation
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT (run_id, device_id, check_item_id) DO UPDATE SET
                result_status=EXCLUDED.result_status,
                result_value=EXCLUDED.result_value,
                evidence=EXCLUDED.evidence,
                recommendation=EXCLUDED.recommendation,
                checked_at=NOW()
            """,
            run_id,
            device_id,
            check_item_id,
            item["status"],
            item.get("value"),
            item.get("evidence"),
            item.get("recommendation"),
        )

    logger.info("Imported check report %s run_id=%s rows=%s", filename, run_id, len(rows))
    return {"id": run_id, "run_type": run_type, "imported_results": len(rows), "stored_name": stored_name}


def _mime_type(filename: str) -> str:
    suffix = Path(filename).suffix.lower()
    return {
        ".csv": "text/csv",
        ".html": "text/html",
        ".htm": "text/html",
        ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    }.get(suffix, "application/octet-stream")
