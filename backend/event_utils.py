"""
Event de-duplication helpers.

An unresolved event should stay as a single row even when the collector sees
the same condition on every polling cycle. Numeric readings are normalized so
CPU 75.7% and CPU 76.1% are treated as the same event type until resolved.
"""
import json
import re
from typing import Optional


VALUE_RE = re.compile(r"(?<![\w./-])\d+(?:\.\d+)?(?=\s*(?:%|째C|°C|\?C|C\b|GB|MB|bps|pps))")
SPACE_RE = re.compile(r"\s+")
ZSCORE_RE = re.compile(r"(Z-score:\s*)[-+]?\d+(?:\.\d+)?", re.IGNORECASE)


def event_dedupe_key(device_id: Optional[int], severity: str, category: str, message: str) -> tuple:
    normalized_message = VALUE_RE.sub("#", message or "")
    normalized_message = ZSCORE_RE.sub(r"\1#", normalized_message)
    normalized_message = SPACE_RE.sub(" ", normalized_message).strip()
    return (
        device_id,
        (severity or "").strip().lower(),
        (category or "").strip(),
        normalized_message,
    )


async def find_unresolved_duplicate_event(
    conn,
    device_id: Optional[int],
    severity: str,
    category: str,
    message: str,
) -> Optional[int]:
    target_key = event_dedupe_key(device_id, severity, category, message)
    rows = await conn.fetch(
        """
        SELECT id, message
        FROM events
        WHERE device_id IS NOT DISTINCT FROM $1
          AND lower(severity) = lower($2)
          AND category IS NOT DISTINCT FROM $3
          AND status IN ('active', 'acknowledged')
        ORDER BY time DESC
        """,
        device_id,
        severity,
        category,
    )
    for row in rows:
        row_key = event_dedupe_key(device_id, severity, category, row["message"])
        if row_key == target_key:
            return row["id"]
    return None


async def save_event_once(conn, device_id, severity, category, message, occurred_at=None):
    """Serialize duplicate lookup and insert across collectors and workers."""
    key = json.dumps(event_dedupe_key(device_id, severity, category, message))
    async with conn.transaction():
        await conn.execute("SELECT pg_advisory_xact_lock(hashtext($1)::bigint)", key)
        if await find_unresolved_duplicate_event(conn, device_id, severity, category, message):
            return None
        return await conn.fetchrow(
            """
            INSERT INTO events (time, device_id, severity, category, message, status)
            VALUES (COALESCE($1::timestamptz, NOW()), $2, $3, $4, $5, 'active')
            RETURNING id, time
            """,
            occurred_at, device_id, severity, category, message,
        )


async def claim_event_email(conn, event_id: int, recipients: str) -> Optional[int]:
    """Commit a single delivery attempt before contacting the SMTP server."""
    async with conn.transaction():
        event = await conn.fetchval(
            """SELECT id FROM events
               WHERE id=$1 AND status IN ('active', 'acknowledged') FOR UPDATE""",
            event_id,
        )
        if event is None:
            return None
        existing = await conn.fetchval(
            "SELECT id FROM notification_log WHERE event_id=$1 AND channel='email' LIMIT 1",
            event_id,
        )
        if existing is not None:
            return None
        return await conn.fetchval(
            """INSERT INTO notification_log (event_id, channel, recipient, status)
               VALUES ($1, 'email', $2, 'sending') RETURNING id""",
            event_id, recipients,
        )
