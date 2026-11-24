"""Stable agent identity; IP/name conflicts must not merge device histories."""
from typing import Optional

from fastapi import HTTPException
from pydantic import BaseModel, Field


class AgentIdentity(BaseModel):
    agent_id: Optional[str] = Field(default=None, pattern=r'^[0-9a-f]{64}$')


async def init_agent_identity_schema(conn):
    await conn.execute('''
        ALTER TABLE devices ADD COLUMN IF NOT EXISTS agent_id VARCHAR(64);
        CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_agent_identity
            ON devices(agent_id) WHERE agent_id IS NOT NULL;
    ''')


async def report_device(conn, ip_address, agent_id=None):
    if agent_id:
        rows = await conn.fetch('''SELECT id FROM devices WHERE agent_id=$1
            AND ip_address=$2::inet AND type='server' AND enabled=TRUE''', agent_id, str(ip_address))
    else:
        rows = await conn.fetch('''SELECT id FROM devices WHERE ip_address=$1::inet
            AND type='server' AND enabled=TRUE''', str(ip_address))
    if len(rows) != 1:
        raise HTTPException(409, 'Agent identity/IP is missing, stale or ambiguous. Register this server first; do not merge devices by name.')
    return rows[0]['id']
