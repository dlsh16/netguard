"""JWT token creation/verification and password hashing — Python builtins only (no extra packages)."""
import base64
import hashlib
import hmac
import json
import os
from datetime import datetime, timedelta, timezone


# ─── Password (PBKDF2-HMAC-SHA256, 200 000 iterations) ────────────────────────

def hash_password(password: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 200_000)
    return f"pbkdf2:sha256:200000:{_b64e(salt)}:{_b64e(dk)}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, alg, iters, salt_b64, dk_b64 = stored.split(':')
        salt     = _b64d(salt_b64)
        expected = _b64d(dk_b64)
        candidate = hashlib.pbkdf2_hmac(alg, password.encode('utf-8'), salt, int(iters))
        return hmac.compare_digest(candidate, expected)
    except Exception:
        return False


# ─── JWT (HS256) ───────────────────────────────────────────────────────────────

def create_token(payload: dict, secret: str, expires_hours: int = 8) -> str:
    data = {
        **payload,
        'exp': (datetime.now(timezone.utc) + timedelta(hours=expires_hours)).timestamp()
    }
    header = _b64_json({"alg": "HS256", "typ": "JWT"})
    body   = _b64_json(data)
    sig    = _sign(f"{header}.{body}", secret)
    return f"{header}.{body}.{sig}"


def decode_token(token: str, secret: str) -> dict:
    try:
        header, body, sig = token.split('.')
    except ValueError:
        raise ValueError("잘못된 토큰 형식")
    expected = _sign(f"{header}.{body}", secret)
    if not hmac.compare_digest(expected.encode(), sig.encode()):
        raise ValueError("유효하지 않은 토큰 서명")
    payload = json.loads(_b64d(body))
    if payload.get('exp', 0) < datetime.now(timezone.utc).timestamp():
        raise ValueError("만료된 토큰")
    return payload


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))


def _b64_json(obj: dict) -> str:
    return _b64e(json.dumps(obj, separators=(',', ':')).encode())


def _sign(msg: str, secret: str) -> str:
    return _b64e(hmac.new(secret.encode(), msg.encode(), hashlib.sha256).digest())
