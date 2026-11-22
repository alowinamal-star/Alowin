"""Authentication, role-based access control and rate limiting.

Design notes
------------
* Passwords are hashed with ``hashlib.scrypt`` (memory-hard, stdlib only).
* Access tokens are compact HMAC-SHA256 signed claims (header.payload.signature)
  with an expiry, so no third-party JWT dependency is required.
* The signing key comes from ``PROMPTSHIELD_SECRET`` or is generated once and
  persisted in the store, so tokens survive a process restart.
* Rate limiting is an in-process sliding window (single instance deployment).
  It is intentionally simple and documented as such in the README.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from collections import defaultdict, deque
from typing import Callable, Iterable, Optional

from fastapi import Depends, HTTPException, Request, status

from . import db
from .config import RATE_LIMIT_PER_MINUTE, SECRET_KEY_ENV, TOKEN_TTL_SECONDS

ROLES = ("admin", "analyst", "viewer")

# Capability matrix — the single source of truth for RBAC.
ROLE_CAPABILITIES = {
    "admin": {"scan", "read", "firewall", "approve", "testing", "settings", "audit"},
    "analyst": {"scan", "read", "firewall", "testing"},
    "viewer": {"read"},
}


# --------------------------------------------------------------------------
# Password hashing
# --------------------------------------------------------------------------
_SCRYPT_N = 2**14
_SCRYPT_R = 8
_SCRYPT_P = 1


def hash_password(password: str) -> str:
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters")
    salt = os.urandom(16)
    digest = hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=32
    )
    return "scrypt${}${}${}${}${}".format(
        _SCRYPT_N,
        _SCRYPT_R,
        _SCRYPT_P,
        base64.urlsafe_b64encode(salt).decode(),
        base64.urlsafe_b64encode(digest).decode(),
    )


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, n, r, p, salt_b64, hash_b64 = stored.split("$")
        if scheme != "scrypt":
            return False
        salt = base64.urlsafe_b64decode(salt_b64)
        expected = base64.urlsafe_b64decode(hash_b64)
        candidate = hashlib.scrypt(
            password.encode("utf-8"), salt=salt, n=int(n), r=int(r), p=int(p), dklen=len(expected)
        )
        return hmac.compare_digest(candidate, expected)
    except Exception:
        return False


# --------------------------------------------------------------------------
# Signing key
# --------------------------------------------------------------------------
_key_lock = threading.Lock()


def _signing_key() -> bytes:
    if SECRET_KEY_ENV:
        return SECRET_KEY_ENV.encode("utf-8")
    with _key_lock:
        store = db.get_store()
        record = store.get("settings", "signing_key")
        if record and record.get("value"):
            return record["value"].encode("utf-8")
        generated = secrets.token_urlsafe(48)
        store.insert("settings", {"id": "signing_key", "value": generated})
        return generated.encode("utf-8")


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _b64d(raw: str) -> bytes:
    padding = "=" * (-len(raw) % 4)
    return base64.urlsafe_b64decode(raw + padding)


def create_token(user: dict, ttl_seconds: Optional[int] = None) -> dict:
    ttl = ttl_seconds or TOKEN_TTL_SECONDS
    now = int(time.time())
    claims = {
        "sub": user["id"],
        "email": user["email"],
        "role": user.get("role", "viewer"),
        "iat": now,
        "exp": now + ttl,
    }
    header = _b64e(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    payload = _b64e(json.dumps(claims, separators=(",", ":")).encode())
    signing_input = f"{header}.{payload}".encode()
    signature = _b64e(hmac.new(_signing_key(), signing_input, hashlib.sha256).digest())
    return {"token": f"{header}.{payload}.{signature}", "expires_in": ttl, "claims": claims}


def decode_token(token: str) -> dict:
    try:
        header, payload, signature = token.split(".")
    except ValueError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Malformed token")
    signing_input = f"{header}.{payload}".encode()
    expected = _b64e(hmac.new(_signing_key(), signing_input, hashlib.sha256).digest())
    if not hmac.compare_digest(expected, signature):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid token signature")
    claims = json.loads(_b64d(payload))
    if int(claims.get("exp", 0)) < int(time.time()):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token expired")
    return claims


# --------------------------------------------------------------------------
# Users
# --------------------------------------------------------------------------
DEFAULT_USERS = [
    {
        "email": "admin@promptshield.ai",
        "name": "Security Administrator",
        "role": "admin",
        "password": os.environ.get("SEED_ADMIN_PASSWORD", "Admin@12345"),
    },
    {
        "email": "analyst@promptshield.ai",
        "name": "SOC Analyst",
        "role": "analyst",
        "password": "Analyst@12345",
    },
    {
        "email": "viewer@promptshield.ai",
        "name": "Read-only Reviewer",
        "role": "viewer",
        "password": "Viewer@12345",
    },
]


def seed_users() -> None:
    store = db.get_store()
    existing = {u["email"] for u in store.find("users", limit=1000)}
    for seed in DEFAULT_USERS:
        if seed["email"] in existing:
            continue
        store.insert(
            "users",
            {
                "id": db.new_id("usr"),
                "email": seed["email"],
                "name": seed["name"],
                "role": seed["role"],
                "password_hash": hash_password(seed["password"]),
                "created_at": db.utcnow(),
            },
        )


def find_user_by_email(email: str) -> Optional[dict]:
    email = (email or "").strip().lower()
    users = db.get_store().find("users", lambda u: u.get("email", "").lower() == email, limit=1)
    return users[0] if users else None


def get_user(user_id: str) -> Optional[dict]:
    return db.get_store().get("users", user_id)


def create_user(email: str, name: str, password: str, role: str = "analyst") -> dict:
    email = email.strip().lower()
    if not email or "@" not in email:
        raise HTTPException(400, "A valid email address is required")
    if role not in ROLES:
        raise HTTPException(400, f"role must be one of {ROLES}")
    if find_user_by_email(email):
        raise HTTPException(409, "A user with that email already exists")
    try:
        hashed = hash_password(password)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    user = db.get_store().insert(
        "users",
        {
            "id": db.new_id("usr"),
            "email": email,
            "name": name.strip() or email,
            "role": role,
            "password_hash": hashed,
            "created_at": db.utcnow(),
        },
    )
    db.audit(email, "user.created", f"role={role}")
    return user


def public_user(user: dict) -> dict:
    return {
        "id": user.get("id"),
        "email": user.get("email"),
        "name": user.get("name"),
        "role": user.get("role"),
        "created_at": user.get("created_at"),
        "capabilities": sorted(ROLE_CAPABILITIES.get(user.get("role", "viewer"), set())),
    }


# --------------------------------------------------------------------------
# Request dependencies
# --------------------------------------------------------------------------
def _bearer(request: Request) -> Optional[str]:
    header = request.headers.get("authorization", "")
    if header.lower().startswith("bearer "):
        return header[7:].strip()
    # Browser download helper for report endpoints.
    return request.query_params.get("token")


def current_user(request: Request) -> dict:
    token = _bearer(request)
    if not token:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    claims = decode_token(token)
    user = get_user(claims.get("sub", ""))
    if not user or not user.get("active", True):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "User no longer active")
    return user


def require(*capabilities: str) -> Callable[[dict], dict]:
    """Dependency factory: caller must hold every listed capability."""

    def dependency(user: dict = Depends(current_user)) -> dict:
        granted = ROLE_CAPABILITIES.get(user.get("role", "viewer"), set())
        missing = [c for c in capabilities if c not in granted]
        if missing:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                f"Role '{user.get('role')}' lacks capability: {', '.join(missing)}",
            )
        return user

    return dependency


# --------------------------------------------------------------------------
# Rate limiting
# --------------------------------------------------------------------------
class SlidingWindowLimiter:
    def __init__(self, limit_per_minute: int):
        self.limit = limit_per_minute
        self._hits: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, key: str, cost: int = 1) -> tuple[bool, int]:
        now = time.time()
        window_start = now - 60
        with self._lock:
            bucket = self._hits[key]
            while bucket and bucket[0] < window_start:
                bucket.popleft()
            if len(bucket) + cost > self.limit:
                retry_after = max(1, int(60 - (now - bucket[0]))) if bucket else 60
                return False, retry_after
            for _ in range(cost):
                bucket.append(now)
            return True, 0

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


limiter = SlidingWindowLimiter(RATE_LIMIT_PER_MINUTE)


def client_key(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def capabilities_for(role: str) -> Iterable[str]:
    return ROLE_CAPABILITIES.get(role, set())
