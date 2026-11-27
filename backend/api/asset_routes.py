import asyncio
from datetime import datetime
from fastapi import APIRouter, Request
from fastapi.responses import Response
from api.routes import _require_admin
from asset_export import build_asset_workbook
from database import get_db_pool

router=APIRouter(prefix='/api/assets',tags=['assets'])


@router.get('/export.xlsx')
async def export_assets(request:Request):
    _require_admin(request)
    pool=await get_db_pool()
    async with pool.acquire() as conn,conn.transaction(isolation='repeatable_read',readonly=True):
        devices=[dict(r) for r in await conn.fetch('SELECT id,name,type,host(ip_address) AS ip_address,os_version,location FROM devices ORDER BY type,name')]
        software=[dict(r) for r in await conn.fetch('SELECT device_id,name,version FROM software_inventory WHERE present')]
    data=await asyncio.to_thread(build_asset_workbook,devices,software)
    return Response(data,media_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                    headers={'Content-Disposition':'attachment; filename="NetGuard-assets-{}.xlsx"'.format(datetime.now().strftime('%Y%m%d')),'Cache-Control':'no-store'})
