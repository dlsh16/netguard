"""Two consecutive valid observations confirm a link transition, never a timeout."""
from datetime import datetime, timezone
import re

LOGICAL = re.compile(r'^(vlan|vlan-interface|null|loopback|lo\d|tunnel)', re.I)


def observe(previous, iface, now):
    status = iface.get('status')
    valid = status in ('up', 'down') and iface.get('admin_status') == 'up'
    valid = valid and not LOGICAL.match(str(iface.get('name', '')))
    row = dict(previous or {})
    stable = row.get('stable')
    if not valid:
        row.update(candidate=None, samples=0)
        return row, None
    gap = row.get('last_seen') and (now - row['last_seen']).total_seconds() > 300
    count = row.get('samples', 0) + 1 if row.get('candidate') == status and not gap else 1
    transition = (stable, status) if count >= 2 and stable and stable != status else None
    row.update(stable=status if count >= 2 else stable, candidate=status,
               samples=min(count, 2), last_seen=now)
    return row, transition


async def monitor_links(pool, results):
    alerts, resolved = [], []
    now = datetime.now(timezone.utc)
    async with pool.acquire() as conn:
        for device in results:
            if device.get('type') != 'switch' or not device.get('device_id'):
                continue
            device_id = int(device['device_id'])
            async with conn.transaction():
                await conn.execute("SELECT pg_advisory_xact_lock(hashtext('netguard_links'),$1)", device_id)
                previous = {r['if_index']: dict(r) for r in await conn.fetch(
                    'SELECT * FROM switch_link_state WHERE device_id=$1', device_id)}
                seen = set()
                for iface in device.get('metrics', {}).get('interfaces', []):
                    index = iface.get('index')
                    if not isinstance(index, int):
                        continue
                    seen.add(index)
                    old = previous.get(index, {})
                    row, transition = observe(old, iface, now)
                    name = str(iface.get('name') or index)
                    event_id = old.get('event_id')
                    if row.get('samples') == 2 and row.get('stable') == 'up':
                        # Recover old-format incidents only after an observed stable Up.
                        closed = await conn.fetch('''UPDATE events SET status='resolved',resolved_at=NOW()
                            WHERE device_id=$1 AND status IN ('active','acknowledged')
                            AND (id=$2 OR (category='네트워크' AND message=$3)) RETURNING id''',
                            device_id, event_id, '포트 ' + name + ' 다운 감지')
                        resolved.extend(r['id'] for r in closed)
                        event_id = None
                    if transition:
                        state = transition[1]
                        message = '포트 {} 링크 {} ({} → {})'.format(name, state.upper(), transition[0].upper(), state.upper())
                        severity = 'warning' if state == 'down' else 'info'
                        event = await conn.fetchrow('''INSERT INTO events(device_id,severity,category,message,status)
                            VALUES($1,$2,'네트워크',$3,'active') RETURNING id,time''', device_id, severity, message)
                        alerts.append(dict(device=device['device'], device_id=device_id, severity=severity,
                                           category='네트워크', message=message, id=event['id'],
                                           timestamp=event['time'].isoformat(), link_recovery=state == 'up'))
                        if state == 'down':
                            event_id = event['id']
                    await conn.execute('''INSERT INTO switch_link_state
                        (device_id,if_index,name,stable,candidate,samples,last_seen,event_id)
                        VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(device_id,if_index) DO UPDATE SET
                        name=EXCLUDED.name,stable=EXCLUDED.stable,candidate=EXCLUDED.candidate,
                        samples=EXCLUDED.samples,last_seen=EXCLUDED.last_seen,event_id=EXCLUDED.event_id''',
                        device_id,index,name,row.get('stable'),row.get('candidate'),row.get('samples',0),
                        row.get('last_seen',now),event_id)
                await conn.execute('''UPDATE switch_link_state SET candidate=NULL,samples=0
                    WHERE device_id=$1 AND NOT(if_index=ANY($2::int[]))''',device_id,list(seen))
    return alerts, resolved
