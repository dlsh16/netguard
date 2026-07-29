"""
TimescaleDB (PostgreSQL) connection and schema initialization.
"""
import json
import logging
from datetime import datetime
from typing import Optional

import asyncpg

from config import settings

logger = logging.getLogger('netguard.db')

_pool: Optional[asyncpg.Pool] = None


async def get_db_pool() -> asyncpg.Pool:
    global _pool
    if _pool is None:
        _pool = await asyncpg.create_pool(
            host=settings.DB_HOST,
            port=settings.DB_PORT,
            user=settings.DB_USER,
            password=settings.DB_PASSWORD,
            database=settings.DB_NAME,
            min_size=2,
            max_size=10,
            command_timeout=30,
        )
    return _pool


async def close_db_pool():
    global _pool
    if _pool:
        await _pool.close()
        _pool = None


async def init_db():
    """Create TimescaleDB hypertables and supporting tables."""
    pool = await get_db_pool()
    async with pool.acquire() as conn:
        await conn.execute("SELECT pg_advisory_lock(hashtext('netguard_schema_init'));")
        try:
            await _init_db_locked(conn)
        finally:
            await conn.execute("SELECT pg_advisory_unlock(hashtext('netguard_schema_init'));")


async def _init_db_locked(conn):
    """Initialize schema while holding the process-wide DB advisory lock."""
    # TimescaleDB extension (optional ??plain PostgreSQL works without it)
    try:
        await conn.execute("CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;")
    except Exception as e:
        logger.warning(f"TimescaleDB extension not available (dev mode): {e}")

    # --- Devices ---
    await conn.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            id          SERIAL PRIMARY KEY,
            name        VARCHAR(100) UNIQUE NOT NULL,
            type        VARCHAR(50)  NOT NULL,  -- server/switch/env/ups/rpi
            ip_address  INET         NOT NULL,
            snmp_version VARCHAR(10) DEFAULT 'v2c',
            community   VARCHAR(100) DEFAULT 'public',
            snmp_v3_user VARCHAR(100),
            snmp_v3_auth VARCHAR(200),
            snmp_v3_priv VARCHAR(200),
            snmp_v3_security_level VARCHAR(20) DEFAULT 'authPriv',
            snmp_v3_auth_protocol VARCHAR(20) DEFAULT 'SHA',
            snmp_v3_priv_protocol VARCHAR(20) DEFAULT 'AES',
            os_version  VARCHAR(200),
            location    VARCHAR(200),
            enabled     BOOLEAN      DEFAULT TRUE,
            created_at  TIMESTAMPTZ  DEFAULT NOW(),
            updated_at  TIMESTAMPTZ  DEFAULT NOW()
        );
    """)
    for column, ddl in [
        ("snmp_v3_security_level", "ALTER TABLE devices ADD COLUMN IF NOT EXISTS snmp_v3_security_level VARCHAR(20) DEFAULT 'authPriv'"),
        ("snmp_v3_auth_protocol", "ALTER TABLE devices ADD COLUMN IF NOT EXISTS snmp_v3_auth_protocol VARCHAR(20) DEFAULT 'SHA'"),
        ("snmp_v3_priv_protocol", "ALTER TABLE devices ADD COLUMN IF NOT EXISTS snmp_v3_priv_protocol VARCHAR(20) DEFAULT 'AES'"),
    ]:
        try:
            await conn.execute(ddl)
        except Exception as e:
            logger.warning(f"Device SNMP v3 column migration failed ({column}): {e}")

    # --- Metrics (hypertable for time-series) ---
    await conn.execute("""
        CREATE TABLE IF NOT EXISTS metrics (
            time        TIMESTAMPTZ  NOT NULL,
            device_id   INTEGER      NOT NULL REFERENCES devices(id),
            metric_name VARCHAR(100) NOT NULL,
            value       DOUBLE PRECISION NOT NULL,
            unit        VARCHAR(20)
        );
    """)
    try:
        await conn.execute("""
            SELECT create_hypertable('metrics','time', if_not_exists => TRUE);
        """)
    except Exception as e:
        logger.warning(f"Hypertable creation (may already exist): {e}")

    # Compression policy (after 7 days)
    try:
        await conn.execute("""
            ALTER TABLE metrics SET (
                timescaledb.compress,
                timescaledb.compress_segmentby = 'device_id,metric_name'
            );
        """)
        await conn.execute("""
            SELECT add_compression_policy('metrics', INTERVAL '7 days', if_not_exists => TRUE);
        """)
    except Exception as e:
        logger.debug(f"Compression policy (may already exist): {e}")

    # Retention policy (keep 90 days by default)
    try:
        await conn.execute("""
            SELECT add_retention_policy('metrics', INTERVAL '90 days', if_not_exists => TRUE);
        """)
    except Exception as e:
        logger.debug(f"Retention policy (may already exist): {e}")

    # --- Events ---
    await conn.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id          SERIAL PRIMARY KEY,
            time        TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
            device_id   INTEGER      REFERENCES devices(id),
            severity    VARCHAR(20)  NOT NULL,  -- critical/warning/info
            category    VARCHAR(50),
            message     TEXT         NOT NULL,
            raw_data    JSONB,
            status      VARCHAR(20)  DEFAULT 'active',  -- active/acknowledged/resolved
            resolved_at TIMESTAMPTZ,
            acknowledged_by VARCHAR(100)
        );
    """)

    # --- Thresholds ---
    await conn.execute("""
        CREATE TABLE IF NOT EXISTS thresholds (
            id          SERIAL PRIMARY KEY,
            device_id   INTEGER      REFERENCES devices(id),
            metric_name VARCHAR(100) NOT NULL,
            warn_value  DOUBLE PRECISION,
            crit_value  DOUBLE PRECISION,
            direction   VARCHAR(10)  DEFAULT 'above',  -- above/below
            enabled     BOOLEAN      DEFAULT TRUE,
            UNIQUE(device_id, metric_name)
        );
    """)

    # --- CVE / Vulnerability tracking ---
    await conn.execute("""
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id          SERIAL PRIMARY KEY,
            cve_id      VARCHAR(30)  UNIQUE NOT NULL,
            cwe_id      VARCHAR(30),
            cvss_score  DECIMAL(4,1),
            cvss_vector VARCHAR(200),
            severity    VARCHAR(20),
            description TEXT,
            published_at TIMESTAMPTZ,
            modified_at  TIMESTAMPTZ,
            raw_data    JSONB
        );
    """)

    await conn.execute("""
        CREATE TABLE IF NOT EXISTS device_vulnerabilities (
            device_id   INTEGER NOT NULL REFERENCES devices(id),
            vuln_id     INTEGER NOT NULL REFERENCES vulnerabilities(id),
            detected_at TIMESTAMPTZ DEFAULT NOW(),
            patched     BOOLEAN DEFAULT FALSE,
            patched_at  TIMESTAMPTZ,
            PRIMARY KEY (device_id, vuln_id)
        );
    """)

    await conn.execute("""
        CREATE TABLE IF NOT EXISTS cve_completions (
            cve_id       VARCHAR(30) PRIMARY KEY,
            completed_at TIMESTAMPTZ DEFAULT NOW(),
            completed_by VARCHAR(100)
        );
    """)

    # --- Server maintenance/security script results ---
    await conn.execute("""
        CREATE TABLE IF NOT EXISTS check_items (
            id          SERIAL PRIMARY KEY,
            code        VARCHAR(100) UNIQUE NOT NULL,
            name        VARCHAR(300) NOT NULL,
            category    VARCHAR(120) NOT NULL,
            severity    VARCHAR(20) DEFAULT 'medium',
            description TEXT,
            created_at  TIMESTAMPTZ DEFAULT NOW()
        );
    """)

    await conn.execute("""
        CREATE TABLE IF NOT EXISTS check_runs (
            id           SERIAL PRIMARY KEY,
            run_type     VARCHAR(40) NOT NULL,
            source_tool  VARCHAR(120),
            report_title VARCHAR(300) NOT NULL,
            status       VARCHAR(30) DEFAULT 'completed',
            started_at   TIMESTAMPTZ,
            completed_at TIMESTAMPTZ DEFAULT NOW(),
            notes        TEXT,
            created_at   TIMESTAMPTZ DEFAULT NOW()
        );
    """)

    await conn.execute("""
        CREATE TABLE IF NOT EXISTS report_files (
            id            SERIAL PRIMARY KEY,
            run_id        INTEGER NOT NULL REFERENCES check_runs(id) ON DELETE CASCADE,
            original_name VARCHAR(300) NOT NULL,
            stored_name   VARCHAR(300) NOT NULL,
            mime_type     VARCHAR(160),
            size_bytes    BIGINT DEFAULT 0,
            storage_path  TEXT NOT NULL,
            uploaded_at   TIMESTAMPTZ DEFAULT NOW()
        );
    """)

    await conn.execute("""
        CREATE TABLE IF NOT EXISTS check_results (
            id              SERIAL PRIMARY KEY,
            run_id          INTEGER NOT NULL REFERENCES check_runs(id) ON DELETE CASCADE,
            device_id       INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
            check_item_id   INTEGER NOT NULL REFERENCES check_items(id) ON DELETE CASCADE,
            result_status   VARCHAR(20) NOT NULL,
            result_value    TEXT,
            evidence        TEXT,
            recommendation  TEXT,
            checked_at      TIMESTAMPTZ DEFAULT NOW(),
            UNIQUE (run_id, device_id, check_item_id)
        );
    """)

    # --- Notification log ---
    await conn.execute("""
        CREATE TABLE IF NOT EXISTS notification_log (
            id          SERIAL PRIMARY KEY,
            time        TIMESTAMPTZ DEFAULT NOW(),
            channel     VARCHAR(20),  -- email/kakao
            recipient   VARCHAR(200),
            event_id    INTEGER REFERENCES events(id),
            status      VARCHAR(20),
            error_msg   TEXT
        );
    """)

    # --- Alert rules ---
    await conn.execute("""
        CREATE TABLE IF NOT EXISTS alert_rules (
            id          SERIAL PRIMARY KEY,
            name        VARCHAR(200) NOT NULL,
            rule_type   VARCHAR(50)  NOT NULL,  -- threshold/anomaly/pattern
            condition   JSONB        NOT NULL,
            action      JSONB        NOT NULL,
            enabled     BOOLEAN      DEFAULT TRUE,
            created_at  TIMESTAMPTZ  DEFAULT NOW()
        );
    """)

    # --- Switch error counter baselines ---
    await conn.execute("""
        CREATE TABLE IF NOT EXISTS switch_error_baselines (
            device_id    INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
            if_index     INTEGER NOT NULL,
            port_name    VARCHAR(200),
            in_baseline  BIGINT DEFAULT 0,
            out_baseline BIGINT DEFAULT 0,
            updated_at   TIMESTAMPTZ DEFAULT NOW(),
            PRIMARY KEY (device_id, if_index)
        );
    """)

    # --- Users ---
    await conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id            SERIAL PRIMARY KEY,
            username      VARCHAR(100) UNIQUE NOT NULL,
            password_hash VARCHAR(300) NOT NULL,
            full_name     VARCHAR(200),
            email         VARCHAR(200),
            role          VARCHAR(20) DEFAULT 'operator',  -- admin / operator
            enabled       BOOLEAN DEFAULT TRUE,
            last_login    TIMESTAMPTZ,
            created_at    TIMESTAMPTZ DEFAULT NOW(),
            updated_at    TIMESTAMPTZ DEFAULT NOW()
        );
    """)

    # --- Changelog ---
    await conn.execute("""
        CREATE TABLE IF NOT EXISTS changelog (
            id           SERIAL PRIMARY KEY,
            version      VARCHAR(30)  NOT NULL,
            title        VARCHAR(200) NOT NULL,
            body         TEXT,
            changes      JSONB DEFAULT '[]',
            released_at  TIMESTAMPTZ DEFAULT NOW(),
            created_by   VARCHAR(100)
        );
    """)

    # Indexes
    await conn.execute("CREATE INDEX IF NOT EXISTS idx_metrics_device_time ON metrics(device_id, time DESC);")
    await conn.execute("CREATE INDEX IF NOT EXISTS idx_events_time ON events(time DESC);")
    await conn.execute("CREATE INDEX IF NOT EXISTS idx_events_status ON events(status) WHERE status != 'resolved';")
    await conn.execute("CREATE INDEX IF NOT EXISTS idx_check_runs_completed ON check_runs(completed_at DESC);")
    await conn.execute("CREATE INDEX IF NOT EXISTS idx_check_results_device ON check_results(device_id);")
    await conn.execute("CREATE INDEX IF NOT EXISTS idx_check_results_item ON check_results(check_item_id);")
    await conn.execute("CREATE INDEX IF NOT EXISTS idx_check_results_status ON check_results(result_status);")
    await conn.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS ux_thresholds_global_metric
        ON thresholds(metric_name)
        WHERE device_id IS NULL;
    """)

    # ?? Seed: default admin user ????????????????????????????????????????????
    user_count = await conn.fetchval("SELECT COUNT(*) FROM users")
    if user_count == 0:
        from auth.jwt_handler import hash_password
        await conn.execute("""
            INSERT INTO users (username, password_hash, full_name, role)
            VALUES ('admin', $1, '시스템 관리자', 'admin')
        """, hash_password("admin1234!"))
        logger.info("Default admin user created (username: admin / password: admin1234!)")

    # ?? Seed: initial changelog ?????????????????????????????????????????????
    cl_count = await conn.fetchval("SELECT COUNT(*) FROM changelog")
    if cl_count == 0:
        seed_entries = [
            ("v1.0.0", "초기 릴리스",
             "NetGuard SNMP 통합 모니터링 대시보드 첫 릴리스",
             ["FastAPI + TimescaleDB 기반 백엔드 구성",
              "SNMP v2c/v3 수집기 구현",
              "실시간 WebSocket 대시보드",
              "서버/스위치/UPS/환경센서 모니터링",
              "CVE 취약점 점검(NVD 로컬 캐시)",
              "이메일 및 카카오톡 알림 시스템"],
             datetime(2025, 3, 1)),
            ("v1.1.0", "대시보드 동적 데이터 반영",
             "요약 카드와 주요 수치를 실수집 데이터로 동적 업데이트",
             ["대시보드 요약 카드 실시간 반영",
              "알림 배너 하드코딩 제거",
              "사이드바 배지 동적 업데이트",
              "온습도 및 UPS 수치 매핑 보정",
              "보안 페이지 CVE 통계 동적 업데이트",
              "CVE 데이터 초기 로드 병렬 처리"],
             datetime(2025, 5, 1)),
            ("v1.2.0", "로그인, 사용자 관리, 업데이트 이력",
             "JWT 인증 및 사용자 관리 기능 추가",
             ["JWT 기반 로그인 인증",
              "사용자 추가/수정/삭제 및 비밀번호 변경",
              "역할 기반 접근 제어(관리자/운영자)",
              "업데이트 이력 페이지",
              "로그아웃 및 세션 토큰 관리"],
             datetime(2026, 5, 8)),
        ]
        await conn.executemany("""
            INSERT INTO changelog (version, title, body, changes, created_by, released_at)
            VALUES ($1, $2, $3, $4::jsonb, 'system', $5)
        """, [(v, t, b, json.dumps(c, ensure_ascii=False), d) for v, t, b, c, d in seed_entries])
        logger.info("Initial changelog seeded")

    logger.info("Database schema initialized successfully")
