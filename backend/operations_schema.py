"""Additive schema for advisories, outbound agent jobs and link observations."""


async def init_operations_schema(conn):
    await conn.execute('''
        CREATE TABLE IF NOT EXISTS security_advisories (
            id TEXT PRIMARY KEY, provider TEXT NOT NULL, title TEXT NOT NULL,
            url TEXT NOT NULL, summary TEXT NOT NULL, published_at TIMESTAMPTZ,
            received_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
        CREATE INDEX IF NOT EXISTS idx_advisory_published ON security_advisories(published_at DESC);
        CREATE TABLE IF NOT EXISTS advisory_sync (
            provider TEXT PRIMARY KEY, attempted_at TIMESTAMPTZ, succeeded_at TIMESTAMPTZ,
            error TEXT, item_count INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS agent_check_access (
            device_id INTEGER PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
            token_hash TEXT UNIQUE NOT NULL, last_seen TIMESTAMPTZ,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
        CREATE TABLE IF NOT EXISTS agent_check_jobs (
            id BIGSERIAL PRIMARY KEY, device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
            run_type TEXT NOT NULL CHECK(run_type IN ('security','maintenance')),
            status TEXT NOT NULL DEFAULT 'queued', requested_by TEXT NOT NULL,
            requested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), started_at TIMESTAMPTZ,
            completed_at TIMESTAMPTZ, run_id INTEGER REFERENCES check_runs(id) ON DELETE SET NULL,
            detail TEXT NOT NULL DEFAULT ''
        );
        CREATE UNIQUE INDEX IF NOT EXISTS idx_check_job_active ON agent_check_jobs(device_id)
            WHERE status IN ('queued','running');
        CREATE INDEX IF NOT EXISTS idx_check_job_history ON agent_check_jobs(requested_at DESC);
        CREATE TABLE IF NOT EXISTS switch_link_state (
            device_id INTEGER REFERENCES devices(id) ON DELETE CASCADE, if_index INTEGER,
            name TEXT NOT NULL, stable TEXT, candidate TEXT, samples INTEGER NOT NULL DEFAULT 0,
            last_seen TIMESTAMPTZ NOT NULL, event_id INTEGER REFERENCES events(id) ON DELETE SET NULL,
            PRIMARY KEY(device_id,if_index)
        );
    ''')
