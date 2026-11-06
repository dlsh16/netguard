"""Persistent software snapshots and parameterized inventory searches."""
import csv
import hashlib
import io
import json
from datetime import datetime, timedelta, timezone
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress, field_validator, model_validator


Source = Literal['registry', 'rpm', 'dpkg', 'process', 'tomcat', 'configured']


class SoftwareItem(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    name: str = Field(min_length=1, max_length=300)
    version: str = Field(default='', max_length=150)
    installation_path: str = Field(default='', max_length=1024)
    publisher: str = Field(default='', max_length=300)
    source: Source


class SoftwareReport(BaseModel):
    hostname: str = Field(min_length=1, max_length=100)
    ip_address: IPvAnyAddress
    collected_at: datetime
    os_family: Literal['windows', 'linux', 'other'] = 'other'
    agent_version: str = Field(default='', max_length=30)
    items: list[SoftwareItem] = Field(default_factory=list, max_length=10000)
    complete_sources: list[Source] = Field(default_factory=list, max_length=6)
    errors: list[str] = Field(default_factory=list, max_length=20)

    @field_validator('collected_at')
    @classmethod
    def aware_time(cls, value):
        if value.tzinfo is None or value > datetime.now(timezone.utc) + timedelta(minutes=5):
            raise ValueError('collected_at must include a timezone and cannot be in the future')
        return value.astimezone(timezone.utc)

    @field_validator('errors')
    @classmethod
    def bounded_errors(cls, values):
        if any(len(value) > 300 for value in values):
            raise ValueError('Collection error text is too long')
        return values


class SoftwareFilter(BaseModel):
    field: Literal['server_name', 'ip_address', 'software_name', 'software_version']
    op: Literal['contains', 'equals', 'not_contains', 'starts_with', 'is_empty'] = 'contains'
    value: str = Field(default='', max_length=200)

    @model_validator(mode='after')
    def validate_value(self):
        self.value = self.value.strip()
        if self.op != 'is_empty' and not self.value:
            raise ValueError('검색값을 입력하세요.')
        return self


async def init_inventory_schema(conn):
    await conn.execute('''
        CREATE TABLE IF NOT EXISTS software_inventory (
            id BIGSERIAL PRIMARY KEY,
            device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
            fingerprint CHAR(64) NOT NULL,
            name VARCHAR(300) NOT NULL,
            version VARCHAR(150) NOT NULL DEFAULT '',
            installation_path VARCHAR(1024) NOT NULL DEFAULT '',
            publisher VARCHAR(300) NOT NULL DEFAULT '',
            source VARCHAR(30) NOT NULL,
            first_seen TIMESTAMPTZ NOT NULL,
            last_seen TIMESTAMPTZ NOT NULL,
            present BOOLEAN NOT NULL DEFAULT TRUE,
            UNIQUE(device_id, fingerprint)
        );
        CREATE INDEX IF NOT EXISTS idx_software_device_present ON software_inventory(device_id, present);
        CREATE INDEX IF NOT EXISTS idx_software_name ON software_inventory(lower(name)) WHERE present=TRUE;
        CREATE TABLE IF NOT EXISTS software_inventory_status (
            device_id INTEGER PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
            collected_at TIMESTAMPTZ NOT NULL,
            received_at TIMESTAMPTZ NOT NULL,
            os_family VARCHAR(20) NOT NULL,
            agent_version VARCHAR(30) NOT NULL,
            status VARCHAR(20) NOT NULL,
            item_count INTEGER NOT NULL,
            errors JSONB NOT NULL DEFAULT '[]'
        );
    ''')


def fingerprint(item):
    value = [item.source, item.name.casefold(), item.version, item.installation_path]
    return hashlib.sha256(json.dumps(value, ensure_ascii=False).encode('utf-8')).hexdigest()


async def save_inventory(conn, device_id, report):
    now = datetime.now(timezone.utc)
    async with conn.transaction():
        await conn.execute("SELECT pg_advisory_xact_lock(hashtext('netguard_software'), $1)", device_id)
        previous = await conn.fetchval('SELECT collected_at FROM software_inventory_status WHERE device_id=$1', device_id)
        if previous and report.collected_at <= previous:
            return {'status': 'ignored', 'reason': 'older_or_duplicate_snapshot'}
        unique = {fingerprint(item): item for item in report.items}
        # Only successfully enumerated sources can retire earlier entries.
        if report.complete_sources:
            await conn.execute('UPDATE software_inventory SET present=FALSE WHERE device_id=$1 AND source=ANY($2::text[])', device_id, report.complete_sources)
        if unique:
            await conn.executemany('''
                INSERT INTO software_inventory(device_id,fingerprint,name,version,installation_path,publisher,source,first_seen,last_seen,present)
                VALUES($1,$2,$3,$4,$5,$6,$7,$8,$8,TRUE)
                ON CONFLICT(device_id,fingerprint) DO UPDATE SET
                    name=EXCLUDED.name,publisher=EXCLUDED.publisher,last_seen=EXCLUDED.last_seen,present=TRUE
            ''', [(device_id, key, item.name, item.version, item.installation_path, item.publisher, item.source, report.collected_at) for key, item in unique.items()])
        status = 'partial' if report.errors and (unique or report.complete_sources) else 'failed' if report.errors else 'complete'
        await conn.execute('''
            INSERT INTO software_inventory_status(device_id,collected_at,received_at,os_family,agent_version,status,item_count,errors)
            VALUES($1,$2,$3,$4,$5,$6,$7,$8::jsonb)
            ON CONFLICT(device_id) DO UPDATE SET collected_at=EXCLUDED.collected_at,received_at=EXCLUDED.received_at,
                os_family=EXCLUDED.os_family,agent_version=EXCLUDED.agent_version,status=EXCLUDED.status,
                item_count=EXCLUDED.item_count,errors=EXCLUDED.errors
        ''', device_id, report.collected_at, now, report.os_family, report.agent_version, status, len(unique), json.dumps(report.errors, ensure_ascii=False))
    return {'status': 'ok', 'items': len(unique), 'collection_status': status}


def parse_filters(raw):
    if len(raw) > 8000:
        raise ValueError('검색 조건이 너무 깁니다.')
    values = json.loads(raw)
    if not isinstance(values, list) or len(values) > 20:
        raise ValueError('검색 조건은 최대 20개입니다.')
    return [SoftwareFilter.model_validate(value) for value in values]


def search_where(filters, os_family='', source='', freshness='all', device_id=None):
    clauses = ["d.enabled=TRUE", "d.type='server'", 'i.present=TRUE']
    args = []
    def parameter(value):
        args.append(value)
        return f'${len(args)}'
    fields = {'server_name': 'd.name', 'ip_address': 'host(d.ip_address)', 'software_name': 'i.name', 'software_version': 'i.version'}
    for item in filters:
        column = fields[item.field]
        if item.op == 'is_empty':
            clauses.append(f"{column}=''")
            continue
        value = item.value
        if item.field == 'software_name':
            column = f"replace(lower({column}), 'node.js', 'nodejs')"
            value = value.lower().replace('node.js', 'nodejs')
        bound = parameter(value)
        if item.op == 'equals':
            clauses.append(f'lower({column})=lower({bound})')
        elif item.op == 'starts_with':
            clauses.append(f'left(lower({column}), char_length({bound}))=lower({bound})')
        else:
            operator = '=0' if item.op == 'not_contains' else '>0'
            clauses.append(f'position(lower({bound}) in lower({column})){operator}')
    if os_family:
        if os_family not in ('windows', 'linux', 'other'):
            raise ValueError('OS 필터가 올바르지 않습니다.')
        clauses.append(f's.os_family={parameter(os_family)}')
    if source:
        if source not in ('registry', 'rpm', 'dpkg', 'process', 'tomcat', 'configured'):
            raise ValueError('수집 출처 필터가 올바르지 않습니다.')
        clauses.append(f'i.source={parameter(source)}')
    if freshness not in ('all', 'fresh', 'stale'):
        raise ValueError('수집 시각 필터가 올바르지 않습니다.')
    if freshness != 'all':
        clauses.append("i.last_seen " + (">=" if freshness == 'fresh' else '<') + " NOW()-INTERVAL '24 hours'")
    if device_id is not None:
        clauses.append(f'd.id={parameter(device_id)}')
    return ' AND '.join(clauses), args


GROUP_FROM = '''FROM software_inventory i JOIN devices d ON d.id=i.device_id
                LEFT JOIN software_inventory_status s ON s.device_id=d.id'''
GROUP_KEYS = 'd.id,d.name,d.ip_address,i.name,i.version'


async def search_inventory(conn, filters, *, os_family='', source='', freshness='all', device_id=None,
                           sort='server_name', direction='asc', page=1, page_size=50, export=False):
    orders = {'server_name': 'lower(d.name)', 'ip_address': 'd.ip_address', 'software_name': 'lower(i.name)', 'software_version': 'lower(i.version)'}
    if sort not in orders or direction not in ('asc', 'desc'):
        raise ValueError('정렬 조건이 올바르지 않습니다.')
    where, args = search_where(filters, os_family, source, freshness, device_id)
    base = f'{GROUP_FROM} WHERE {where}'
    stats = await conn.fetchrow(f'''SELECT COUNT(*) AS total, COUNT(DISTINCT device_id) AS servers,
        COUNT(DISTINCT lower(name)) AS products FROM
        (SELECT d.id AS device_id,i.name,i.version {base} GROUP BY {GROUP_KEYS}) g''', *args)
    total = stats['total']
    if export and total > 10000:
        raise ValueError('CSV는 최대 10,000건입니다. 검색 조건을 좁혀 주세요.')
    pages = max(1, (total + page_size - 1) // page_size)
    page = min(page, pages)
    limit, offset = (10000, 0) if export else (page_size, (page - 1) * page_size)
    rows = await conn.fetch(f'''SELECT d.id AS device_id,d.name AS server_name,host(d.ip_address) AS ip_address,
        i.name AS software_name,i.version AS software_version,MAX(i.last_seen) AS last_seen,
        jsonb_agg(jsonb_build_object('path',i.installation_path,'source',i.source,'publisher',i.publisher,
                                    'last_seen',i.last_seen) ORDER BY i.source,i.installation_path) AS installations
        {base} GROUP BY {GROUP_KEYS}
        ORDER BY {orders[sort]} {direction},d.id,i.name,i.version
        LIMIT ${len(args)+1} OFFSET ${len(args)+2}''', *args, limit, offset)
    items = []
    for row in rows:
        item = dict(row)
        if isinstance(item['installations'], str):
            item['installations'] = json.loads(item['installations'])
        items.append(item)
    return {'items': items, 'total': total, 'servers': stats['servers'], 'products': stats['products'],
            'page': page, 'pages': pages, 'page_size': page_size}


async def inventory_coverage(conn):
    rows = await conn.fetch('''SELECT d.id,d.name,host(d.ip_address) AS ip_address,d.snmp_version,
        s.os_family,s.agent_version,s.collected_at,s.received_at,s.status,s.item_count,s.errors,
        (s.collected_at IS NULL OR s.collected_at < NOW()-INTERVAL '24 hours') AS stale
        FROM devices d LEFT JOIN software_inventory_status s ON s.device_id=d.id
        WHERE d.enabled=TRUE AND d.type='server' ORDER BY d.name,d.id''')
    items = []
    for row in rows:
        item = dict(row)
        if isinstance(item['errors'], str):
            item['errors'] = json.loads(item['errors'])
        items.append(item)
    return {'items': items, 'total': len(items), 'reported': sum(i['collected_at'] is not None for i in items),
            'attention': sum(i['stale'] or i['status'] != 'complete' for i in items)}


def inventory_csv(items):
    output = io.StringIO(newline='')
    writer = csv.writer(output)
    writer.writerow(['서버명', 'IP', '소프트웨어 이름', '소프트웨어 버전'])
    for item in items:
        cells = [str(item.get(key) or '') for key in ('server_name', 'ip_address', 'software_name', 'software_version')]
        writer.writerow(["'" + value if value.lstrip().startswith(('=', '+', '-', '@')) or value.startswith(('\t', '\r', '\n')) else value for value in cells])
    return '\ufeff' + output.getvalue()
