"""Admin-only requests, per-device credentials, and at-most-once agent claims."""
import base64
import hashlib
import logging
import secrets
from datetime import datetime
from typing import Literal
from fastapi import APIRouter, Header, HTTPException, Query, Request
from pydantic import BaseModel, Field
from api.routes import _require_admin
from database import get_db_pool
from security.check_reports import parse_report, save_report

router = APIRouter(tags=['remote-checks'])
logger = logging.getLogger('netguard.check_jobs')


class NewJob(BaseModel):
    run_type: Literal['security','maintenance']


class JobResult(BaseModel):
    status: Literal['completed','failed']
    content_base64: str = Field(default='',max_length=5600000)
    detail: str = Field(default='',max_length=500)


async def expire_jobs(conn):
    await conn.execute('''UPDATE agent_check_jobs SET status='expired',completed_at=NOW(),
        detail='Agent did not claim within 15 minutes' WHERE status='queued' AND requested_at<NOW()-INTERVAL '15 minutes';
        UPDATE agent_check_jobs SET status='unknown',completed_at=NOW(),
        detail='Execution result not received; not automatically retried'
        WHERE status='running' AND started_at<NOW()-INTERVAL '45 minutes';''')


@router.get('/api/security/checks/agents')
async def servers():
    pool = await get_db_pool()
    async with pool.acquire() as conn:
        await expire_jobs(conn)
        rows = await conn.fetch('''SELECT d.id,d.name,host(d.ip_address) AS ip_address,d.snmp_version,
            a.last_seen,a.device_id IS NOT NULL AS enrolled,j.status,j.run_type,j.requested_at,j.id AS job_id
            FROM devices d LEFT JOIN agent_check_access a ON a.device_id=d.id
            LEFT JOIN LATERAL (SELECT * FROM agent_check_jobs WHERE device_id=d.id ORDER BY id DESC LIMIT 1) j ON TRUE
            WHERE d.type='server' AND d.enabled ORDER BY d.name''')
    return [dict(r) for r in rows]


@router.post('/api/security/checks/agents/{device_id}/enroll')
async def enroll(device_id:int,request:Request):
    _require_admin(request)
    token = secrets.token_hex(32)
    pool = await get_db_pool()
    async with pool.acquire() as conn, conn.transaction():
        await conn.execute("SELECT pg_advisory_xact_lock(hashtext('netguard_check_job'),$1)",device_id)
        if not await conn.fetchval("SELECT id FROM devices WHERE id=$1 AND enabled AND type='server' AND snmp_version='agent'",device_id):
            raise HTTPException(400,'Agent 서버만 연결할 수 있습니다.')
        if await conn.fetchval("SELECT id FROM agent_check_jobs WHERE device_id=$1 AND status IN ('queued','running')",device_id):
            raise HTTPException(409,'진행 중인 점검이 있어 연결키를 변경할 수 없습니다.')
        await conn.execute('''INSERT INTO agent_check_access(device_id,token_hash) VALUES($1,$2)
            ON CONFLICT(device_id) DO UPDATE SET token_hash=$2,last_seen=NULL,created_at=NOW()''',device_id,hashlib.sha256(token.encode()).hexdigest())
    logger.info('Remote check credential issued: device_id=%s actor=%s',device_id,request.state.user.get('sub'))
    return {'remote_checks':{'enabled':True,'token':token}}


@router.post('/api/security/checks/agents/{device_id}/jobs')
async def create_job(device_id:int,body:NewJob,request:Request):
    _require_admin(request)
    pool = await get_db_pool()
    async with pool.acquire() as conn, conn.transaction():
        await conn.execute("SELECT pg_advisory_xact_lock(hashtext('netguard_check_job'),$1)",device_id)
        await expire_jobs(conn)
        available = await conn.fetchval('''SELECT a.device_id FROM agent_check_access a JOIN devices d ON d.id=a.device_id
            WHERE a.device_id=$1 AND d.enabled AND d.snmp_version='agent' AND a.last_seen>NOW()-INTERVAL '5 minutes' ''',device_id)
        if not available:
            raise HTTPException(409,'원격 점검 Agent 연결이 필요합니다. 연결키 설정 및 Agent 로그를 확인하세요.')
        existing = await conn.fetchrow("SELECT id,status FROM agent_check_jobs WHERE device_id=$1 AND status IN ('queued','running')",device_id)
        if existing:
            raise HTTPException(409,'이미 대기 또는 실행 중인 점검이 있습니다.')
        row = await conn.fetchrow('''INSERT INTO agent_check_jobs(device_id,run_type,requested_by)
            VALUES($1,$2,$3) RETURNING *''',device_id,body.run_type,str(request.state.user.get('sub','admin')))
    logger.info('Check requested: job=%s device=%s type=%s',row['id'],device_id,body.run_type)
    return dict(row)


@router.get('/api/security/checks/jobs')
async def jobs(device_id:int|None=None,since:datetime|None=None,until:datetime|None=None,
               page:int=Query(1,ge=1)):
    if any(value and value.tzinfo is None for value in (since,until)):
        raise HTTPException(400,'조회 일시는 시간대 정보가 필요합니다.')
    if since and until and since>until:
        raise HTTPException(400,'날짜 범위를 확인하세요.')
    pool = await get_db_pool()
    async with pool.acquire() as conn:
        await expire_jobs(conn)
        rows = await conn.fetch('''SELECT j.*,d.name,host(d.ip_address) AS ip_address FROM agent_check_jobs j
            JOIN devices d ON d.id=j.device_id WHERE ($1::int IS NULL OR device_id=$1)
            AND ($2::timestamptz IS NULL OR requested_at >= $2) AND ($3::timestamptz IS NULL OR requested_at < $3)
            ORDER BY requested_at DESC,id DESC LIMIT 51 OFFSET $4''',device_id,since,until,(page-1)*50)
    return {'items':[dict(r) for r in rows[:50]],'has_more':len(rows)>50,'page':page}


@router.post('/api/security/checks/jobs/{job_id}/cancel')
async def cancel(job_id:int,request:Request):
    _require_admin(request)
    pool=await get_db_pool()
    async with pool.acquire() as conn:
        row=await conn.fetchrow("UPDATE agent_check_jobs SET status='cancelled',completed_at=NOW() WHERE id=$1 AND status='queued' RETURNING id",job_id)
    if not row:
        raise HTTPException(409,'대기 중인 작업만 취소할 수 있습니다.')
    return {'status':'cancelled'}


async def authenticate(conn,token):
    if not token or len(token)!=64:
        raise HTTPException(403,'Invalid remote check token')
    row=await conn.fetchrow('''SELECT a.device_id,d.name,host(d.ip_address) AS ip_address,d.os_version
        FROM agent_check_access a JOIN devices d ON d.id=a.device_id
        WHERE token_hash=$1 AND d.enabled AND d.type='server' AND d.snmp_version='agent' ''',hashlib.sha256(token.encode()).hexdigest())
    if not row:
        raise HTTPException(403,'Invalid remote check token')
    await conn.execute('UPDATE agent_check_access SET last_seen=NOW() WHERE device_id=$1',row['device_id'])
    return row


@router.post('/api/agent/check-jobs/poll')
async def poll(x_check_token:str|None=Header(None)):
    pool=await get_db_pool()
    async with pool.acquire() as conn, conn.transaction():
        device=await authenticate(conn,x_check_token)
        await expire_jobs(conn)
        row=await conn.fetchrow('''UPDATE agent_check_jobs SET status='running',started_at=NOW()
            WHERE id=(SELECT id FROM agent_check_jobs WHERE device_id=$1 AND status='queued'
            ORDER BY id FOR UPDATE SKIP LOCKED LIMIT 1) RETURNING id,run_type''',device['device_id'])
    return {'job':dict(row) if row else None}


@router.post('/api/agent/check-jobs/{job_id}/result')
async def result(job_id:int,body:JobResult,x_check_token:str|None=Header(None)):
    pool=await get_db_pool()
    async with pool.acquire() as conn, conn.transaction():
        device=await authenticate(conn,x_check_token)
        job=await conn.fetchrow('SELECT * FROM agent_check_jobs WHERE id=$1 AND device_id=$2 FOR UPDATE',job_id,device['device_id'])
        if not job:
            raise HTTPException(404,'Unknown check job')
        if job['status'] in ('completed','failed'):
            return {'status':job['status'],'run_id':job['run_id']}
        if job['status'] not in ('running','unknown'):
            raise HTTPException(409,'Check job was not claimed')
        run_id=None
        if body.status=='completed':
            try:
                data=base64.b64decode(body.content_base64,validate=True)
            except ValueError as exc:
                raise HTTPException(400,'Invalid base64 report') from exc
            if len(data)>4*1024*1024:
                raise HTTPException(413,'Report exceeds 4 MiB')
            filename='remote_{}_{}.csv'.format(job['run_type'],job_id)
            options=dict(run_type=job['run_type'],device_id=device['device_id'],hostname=device['name'],
                         ip_address=device['ip_address'],os_type=device['os_version'],started_at=job['started_at'])
            if not parse_report(filename,data,options)['rows']:
                raise HTTPException(400,'No check results found in CSV report')
            report=await save_report(conn,filename,data,options)
            run_id=report['id']
        await conn.execute('''UPDATE agent_check_jobs SET status=$2,completed_at=NOW(),run_id=$3,detail=$4 WHERE id=$1''',
                           job_id,body.status,run_id,body.detail)
    logger.info('Check result saved: job=%s status=%s run=%s',job_id,body.status,run_id)
    return {'status':body.status,'run_id':run_id}
