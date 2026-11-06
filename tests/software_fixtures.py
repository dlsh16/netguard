"""Synthetic software inventory for isolated PostgreSQL tests and preview."""
from datetime import datetime, timedelta, timezone
from software_inventory import SoftwareReport, init_inventory_schema, save_inventory

DEVICES = [
    (1, 'MBCO-MES2', '192.0.2.21', 'Windows Server'),
    (2, 'MBCO-MES2-DEV', '192.0.2.22', 'Windows Server'),
    (3, '업무 서버 / Risk Compliance', '192.0.2.23', 'Rocky Linux'),
    (4, '구형 에이전트 서버', '192.0.2.24', 'Windows Server'),
]


async def seed(conn, count=65):
    await conn.execute('''CREATE TABLE devices(id SERIAL PRIMARY KEY,name TEXT NOT NULL,ip_address INET UNIQUE,
        type TEXT DEFAULT 'server',enabled BOOLEAN DEFAULT TRUE,snmp_version TEXT DEFAULT 'agent',os_version TEXT);
        CREATE TABLE users(id SERIAL PRIMARY KEY,name TEXT); INSERT INTO users(name) VALUES('untouched-admin')''')
    await conn.executemany('INSERT INTO devices(id,name,ip_address,os_version) VALUES($1,$2,$3,$4)', DEVICES)
    await init_inventory_schema(conn)
    for device_id, name, ip, os_version in DEVICES[:3]:
        items = [
            {'name': 'Apache Tomcat', 'version': '10.1.39' if device_id != 2 else '10.1.42', 'installation_path': 'C:/Apps/Tomcat' if device_id < 3 else '/opt/tomcat', 'source': 'tomcat'},
            {'name': 'Node.js', 'version': '22.14.0', 'source': 'registry' if device_id < 3 else 'rpm'},
            {'name': 'PHP', 'version': '8.2.28', 'source': 'registry' if device_id < 3 else 'rpm'},
            {'name': 'Risk & Compliance Management Solution', 'version': '' if device_id == 3 else '3.4.1', 'source': 'configured'},
        ] + [{'name': 'Sample Package %03d' % i, 'version': '1.0', 'source': 'registry' if device_id < 3 else 'rpm'} for i in range(count)]
        report = SoftwareReport(hostname=name, ip_address=ip, collected_at=datetime.now(timezone.utc) - timedelta(hours=30 if device_id == 3 else 1),
                                os_family='windows' if device_id < 3 else 'linux', agent_version='1.2.63', items=items,
                                complete_sources=['registry', 'rpm', 'tomcat', 'configured'])
        await save_inventory(conn, device_id, report)
