"""
Event de-duplication helpers.

An unresolved event should stay as a single row even when the collector sees
the same condition on every polling cycle. Numeric readings are normalized so
CPU 75.7% and CPU 76.1% are treated as the same event type until resolved.
"""
import re
from typing import Optional


VALUE_RE = re.compile(r"(?<![\w./-])\d+(?:\.\d+)?(?=\s*(?:%|째C|°C|\?C|C\b|GB|MB|bps|pps))")
SPACE_RE = re.compile(r"\s+")


def event_dedupe_key(device_id: Optional[int], severity: str, category: str, message: str) -> tuple:
    normalized_message = VALUE_RE.sub("#", message or "")
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
