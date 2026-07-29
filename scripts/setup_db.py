"""
Database setup script — creates TimescaleDB, user, and initial schema.

사용법 (psql superuser로 실행):
    python scripts/setup_db.py

또는 수동으로:
    psql -U postgres -f scripts/setup_db.sql
"""
import asyncio
import sys
import os
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from config import settings

SQL_SETUP = f"""
-- 사용자 생성
DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '{settings.DB_USER}') THEN
    CREATE USER {settings.DB_USER} WITH PASSWORD '{settings.DB_PASSWORD}';
  END IF;
END $$;

-- 데이터베이스 생성
SELECT 'CREATE DATABASE {settings.DB_NAME} OWNER {settings.DB_USER}'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = '{settings.DB_NAME}') \\gexec

-- TimescaleDB 확장 활성화
\\c {settings.DB_NAME}
CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;
GRANT ALL PRIVILEGES ON DATABASE {settings.DB_NAME} TO {settings.DB_USER};
"""


async def main():
    import asyncpg

    print("=== NetGuard Database Setup ===")
    print(f"Host: {settings.DB_HOST}:{settings.DB_PORT}")
    print(f"Database: {settings.DB_NAME}")
    print(f"User: {settings.DB_USER}")

    # Connect as superuser (postgres)
    pg_pass = input("PostgreSQL superuser (postgres) password: ")

    try:
        conn = await asyncpg.connect(
            host=settings.DB_HOST,
            port=settings.DB_PORT,
            user="postgres",
            password=pg_pass,
            database="postgres"
        )

        # Create user
        await conn.execute(f"""
            DO $$ BEGIN
              IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '{settings.DB_USER}') THEN
                CREATE USER {settings.DB_USER} WITH PASSWORD '{settings.DB_PASSWORD}';
              END IF;
            END $$;
        """)
        print(f"✓ User '{settings.DB_USER}' ready")

        # Create database
        db_exists = await conn.fetchval(
            "SELECT 1 FROM pg_database WHERE datname = $1", settings.DB_NAME)
        if not db_exists:
            await conn.execute(f"CREATE DATABASE {settings.DB_NAME} OWNER {settings.DB_USER}")
            print(f"✓ Database '{settings.DB_NAME}' created")
        else:
            print(f"  Database '{settings.DB_NAME}' already exists")

        await conn.close()

        # Connect to the new DB to enable extension
        conn2 = await asyncpg.connect(
            host=settings.DB_HOST, port=settings.DB_PORT,
            user="postgres", password=pg_pass, database=settings.DB_NAME
        )
        await conn2.execute("CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;")
        await conn2.execute(f"GRANT ALL ON SCHEMA public TO {settings.DB_USER};")
        await conn2.close()
        print("✓ TimescaleDB extension enabled")

        # Init schema
        from database import init_db
        await init_db()
        print("✓ Schema initialized")
        print("\nSetup complete! Start the server with: python backend/app.py")

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
