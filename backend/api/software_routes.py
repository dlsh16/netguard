from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import Response
from database import get_db_pool
from software_inventory import parse_filters, search_inventory, inventory_coverage, inventory_csv

router = APIRouter(prefix='/api/software', tags=['software inventory'])


@router.get('/coverage')
async def coverage():
    pool = await get_db_pool()
    async with pool.acquire() as conn:
        return await inventory_coverage(conn)


@router.get('')
@router.get('/export')
async def search(request: Request, filters: str = '[]', os_family: str = '', source: str = '', freshness: str = 'all',
                 device_id: int | None = None, sort: str = 'server_name', direction: str = 'asc',
                 page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=100)):
    return await _search(filters, os_family, source, freshness, device_id, sort, direction, page, page_size, export=request.url.path.endswith('/export'))


async def _search(filters, os_family, source, freshness, device_id, sort, direction, page, page_size, export=False):
    try:
        conditions = parse_filters(filters)
        pool = await get_db_pool()
        async with pool.acquire() as conn:
            async with conn.transaction(isolation='repeatable_read', readonly=True):
                result = await search_inventory(conn, conditions, os_family=os_family, source=source, freshness=freshness,
                                                device_id=device_id, sort=sort, direction=direction, page=page, page_size=page_size, export=export)
        if export:
            return Response(inventory_csv(result['items']), media_type='text/csv; charset=utf-8',
                            headers={'Content-Disposition': 'attachment; filename="netguard-software.csv"'})
        return result
    except ValueError as error:
        raise HTTPException(400, str(error)) from error
