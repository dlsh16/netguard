"""Authentication, user management, and changelog API routes."""
import json
from typing import List, Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from auth.jwt_handler import create_token, hash_password, verify_password
from config import settings
from database import get_db_pool

router = APIRouter()


# ─── Pydantic models ──────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    username: str
    password: str


class UserCreate(BaseModel):
    username:  str
    password:  str
    full_name: Optional[str] = None
    email:     Optional[str] = None
    role:      str = "operator"


class UserUpdate(BaseModel):
    full_name: Optional[str] = None
    email:     Optional[str] = None
    role:      Optional[str] = None
    enabled:   Optional[bool] = None


class PasswordChange(BaseModel):
    current_password: Optional[str] = None  # required for self-change; admin may omit
    new_password: str


class ChangelogCreate(BaseModel):
    version: str
    title:   str
    body:    Optional[str] = None
    changes: List[str] = []


# ─── Auth helpers ─────────────────────────────────────────────────────────────

def _current_user(request: Request) -> dict:
    user = getattr(request.state, 'user', None)
    if not user:
        raise HTTPException(401, "인증이 필요합니다")
    return user


def _require_admin(request: Request) -> dict:
    user = _current_user(request)
    if user.get('role') != 'admin':
        raise HTTPException(403, "관리자 권한이 필요합니다")
    return user


# ─── Auth ─────────────────────────────────────────────────────────────────────

@router.post("/auth/login")
async def login(data: LoginRequest):
    pool = await get_db_pool()
    async with pool.acquire() as conn:
        user = await conn.fetchrow(
            "SELECT * FROM users WHERE username = $1 AND enabled = TRUE", data.username)
    if not user or not verify_password(data.password, user['password_hash']):
        raise HTTPException(401, "아이디 또는 비밀번호가 올바르지 않습니다")
    token = create_token(
        {"sub": str(user['id']), "username": user['username'], "role": user['role']},
        settings.JWT_SECRET,
        settings.JWT_EXPIRE_HOURS,
    )
    async with pool.acquire() as conn:
        await conn.execute("UPDATE users SET last_login = NOW() WHERE id = $1", user['id'])
    return {
        "access_token": token,
        "token_type": "bearer",
        "username": user['username'],
        "full_name": user['full_name'] or user['username'],
        "role": user['role'],
    }


@router.get("/auth/me")
async def me(request: Request):
    user = _current_user(request)
    return {"username": user['username'], "role": user['role']}


# ─── Users ────────────────────────────────────────────────────────────────────

@router.get("/users")
async def list_users(request: Request):
    _require_admin(request)
    pool = await get_db_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT id, username, full_name, email, role, enabled, last_login, created_at "
            "FROM users ORDER BY id"
        )
    return [dict(r) for r in rows]


@router.post("/users", status_code=201)
async def create_user(data: UserCreate, request: Request):
    _require_admin(request)
    if len(data.password) < 8:
        raise HTTPException(400, "비밀번호는 8자 이상이어야 합니다")
    if data.role not in ("admin", "operator"):
        raise HTTPException(400, "role은 admin 또는 operator여야 합니다")
    pool = await get_db_pool()
    try:
        async with pool.acquire() as conn:
            row = await conn.fetchrow("""
                INSERT INTO users (username, password_hash, full_name, email, role)
                VALUES ($1, $2, $3, $4, $5) RETURNING id
            """, data.username, hash_password(data.password),
                data.full_name, data.email, data.role)
        return {"id": row['id'], "status": "created"}
    except Exception as e:
        if "unique" in str(e).lower():
            raise HTTPException(409, f"'{data.username}' 사용자가 이미 존재합니다")
        raise HTTPException(500, str(e))


@router.put("/users/{user_id}")
async def update_user(user_id: int, data: UserUpdate, request: Request):
    _require_admin(request)
    if data.role and data.role not in ("admin", "operator"):
        raise HTTPException(400, "role은 admin 또는 operator여야 합니다")
    updates = {k: v for k, v in data.dict().items() if v is not None}
    if not updates:
        return {"status": "no changes"}
    set_clause = ", ".join(f"{k} = ${i+2}" for i, k in enumerate(updates))
    params = [user_id] + list(updates.values())
    pool = await get_db_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            f"UPDATE users SET {set_clause}, updated_at = NOW() WHERE id = $1", *params)
    return {"status": "updated"}


@router.delete("/users/{user_id}")
async def delete_user(user_id: int, request: Request):
    caller = _require_admin(request)
    if str(user_id) == str(caller.get('sub')):
        raise HTTPException(400, "자기 자신은 삭제할 수 없습니다")
    pool = await get_db_pool()
    async with pool.acquire() as conn:
        await conn.execute("UPDATE users SET enabled = FALSE WHERE id = $1", user_id)
    return {"status": "deleted"}


@router.put("/users/{user_id}/password")
async def change_password(user_id: int, data: PasswordChange, request: Request):
    caller   = _current_user(request)
    is_self  = str(user_id) == str(caller.get('sub'))
    is_admin = caller.get('role') == 'admin'
    if not is_self and not is_admin:
        raise HTTPException(403, "권한이 없습니다")
    if len(data.new_password) < 8:
        raise HTTPException(400, "비밀번호는 8자 이상이어야 합니다")
    pool = await get_db_pool()
    async with pool.acquire() as conn:
        user = await conn.fetchrow("SELECT * FROM users WHERE id = $1", user_id)
    if not user:
        raise HTTPException(404, "사용자를 찾을 수 없습니다")
    if is_self and not is_admin:
        if not data.current_password or not verify_password(data.current_password, user['password_hash']):
            raise HTTPException(400, "현재 비밀번호가 올바르지 않습니다")
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE users SET password_hash = $2, updated_at = NOW() WHERE id = $1",
            user_id, hash_password(data.new_password))
    return {"status": "updated"}


# ─── Changelog ────────────────────────────────────────────────────────────────

@router.get("/changelog")
async def list_changelog(request: Request):
    _current_user(request)
    pool = await get_db_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch("SELECT * FROM changelog ORDER BY released_at DESC")
    return [dict(r) for r in rows]


@router.post("/changelog", status_code=201)
async def add_changelog(data: ChangelogCreate, request: Request):
    caller = _require_admin(request)
    pool = await get_db_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow("""
            INSERT INTO changelog (version, title, body, changes, created_by)
            VALUES ($1, $2, $3, $4::jsonb, $5) RETURNING id
        """, data.version, data.title, data.body,
            json.dumps(data.changes, ensure_ascii=False),
            caller.get('username'))
    return {"id": row['id'], "status": "created"}


@router.delete("/changelog/{entry_id}")
async def delete_changelog(entry_id: int, request: Request):
    _require_admin(request)
    pool = await get_db_pool()
    async with pool.acquire() as conn:
        await conn.execute("DELETE FROM changelog WHERE id = $1", entry_id)
    return {"status": "deleted"}
