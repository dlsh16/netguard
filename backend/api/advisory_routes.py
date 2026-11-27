import asyncio
import re
from fastapi import APIRouter, HTTPException, Query, Request, UploadFile, File
from config import settings
from database import get_db_pool
from api.routes import _require_admin
from security.advisories import families, match_reason, parse_rss, save_advisories, sync_advisories, MAX_FEED

router = APIRouter(prefix='/api/security/advisories',tags=['advisories'])


@router.get('')
async def search_advisories(q: str = Query('',max_length=200), page: int = Query(1,ge=1),
                            page_size: int = Query(20,ge=1,le=100)):
    pool = await get_db_pool()
    async with pool.acquire() as conn:
        term = '%' + q.replace('\\','\\\\').replace('%','\\%').replace('_','\\_') + '%'
        rows = await conn.fetch('''SELECT * FROM security_advisories WHERE title ILIKE $1 OR summary ILIKE $1
            ORDER BY published_at DESC NULLS LAST,id LIMIT $2 OFFSET $3''',term,page_size,(page-1)*page_size)
        total = await conn.fetchval('SELECT count(*) FROM security_advisories WHERE title ILIKE $1 OR summary ILIKE $1',term)
        status = await conn.fetchrow('SELECT * FROM advisory_sync WHERE provider=$1',settings.ADVISORY_PROVIDER)
        inventory = await conn.fetch('''SELECT DISTINCT d.id AS device_id,d.name AS server_name,
            host(d.ip_address) AS ip_address,i.name AS software_name,i.version AS software_version,
            s.received_at AS inventory_at FROM software_inventory i JOIN devices d ON d.id=i.device_id
            LEFT JOIN software_inventory_status s ON s.device_id=d.id
            WHERE d.enabled AND d.type='server' AND i.present
            UNION ALL SELECT d.id,d.name,host(d.ip_address),d.os_version,'',d.updated_at
            FROM devices d WHERE d.enabled AND d.type='server' AND COALESCE(d.os_version,'')<>'' ''')
    def match():
        result = []
        software_families = {r['software_name']:families(r['software_name']) for r in inventory}
        family_index, token_index = {}, {}
        for index, software in enumerate(inventory):
            for family in software_families[software['software_name']]:
                family_index.setdefault(family,set()).add(index)
            tokens = re.findall(r'\w+',software['software_name'].casefold())
            if tokens:
                token_index.setdefault(tokens[0],set()).add(index)
        for row in rows:
            item, matches = dict(row), []
            text = item['title']+' '+item['summary']
            advisory_families = families(text)
            candidates = set()
            for family in advisory_families:
                candidates.update(family_index.get(family,()))
            for token in set(re.findall(r'\w+',text.casefold())):
                candidates.update(token_index.get(token,()))
            for index in sorted(candidates):
                software=inventory[index]
                reason = match_reason(item,software,advisory_families,software_families[software['software_name']])
                if reason:
                    matches.append(dict(software,reason=reason))
            item.update(matches=matches[:200],match_count=len(matches),candidate_only=True)
            result.append(item)
        return result
    items = await asyncio.to_thread(match)
    return dict(items=items,total=total,page=page,page_size=page_size,sync=dict(status) if status else None,
                automatic=settings.ADVISORY_SYNC_ENABLED,interval_seconds=max(300,settings.ADVISORY_SYNC_INTERVAL))


@router.post('/sync')
async def sync_now(request: Request):
    _require_admin(request)
    try:
        return await sync_advisories(await get_db_pool(),settings.ADVISORY_PROVIDER)
    except Exception as exc:
        raise HTTPException(502,'RSS 수신 실패. 방화벽/DNS를 확인하거나 RSS 파일을 반입하세요.') from exc


@router.post('/import')
async def import_rss(request: Request,file: UploadFile = File(...)):
    _require_admin(request)
    data = await file.read(MAX_FEED+1)
    try:
        entries = await asyncio.to_thread(parse_rss,data)
    except Exception as exc:
        raise HTTPException(400,'유효한 KISA 보안공지 RSS XML 파일이 아닙니다.') from exc
    pool = await get_db_pool()
    async with pool.acquire() as conn:
        await save_advisories(conn,entries)
    return {'status':'ok','count':len(entries)}
