"""Authentication endpoints: register, login, current user."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status

from .. import auth, config, db
from ..models import LoginRequest, LoginResponse, RegisterRequest, UserOut

router = APIRouter(prefix="/api/auth", tags=["auth"])

_login_limiter = auth.SlidingWindowLimiter(limit_per_minute=20)


@router.post("/register", response_model=LoginResponse, status_code=status.HTTP_201_CREATED)
def register(payload: RegisterRequest, request: Request) -> LoginResponse:
    allowed, retry_after = _login_limiter.check(f"register:{auth.client_key(request)}")
    if not allowed:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "Too many registration attempts. Try again shortly.",
            headers={"Retry-After": str(retry_after)},
        )
    if auth.find_user_by_email(payload.email):
        raise HTTPException(status.HTTP_409_CONFLICT, "An account with that email already exists.")

    # The first account created becomes the administrator; later self-service
    # signups are analysts so a public deployment cannot be escalated freely.
    role = "admin" if db.get_store().count("users") == 0 else "analyst"
    user = auth.create_user(payload.email, payload.name or payload.email.split("@")[0], payload.password, role)
    token = auth.create_token(user)
    db.audit(user, "auth.register", f"Account created with role {role}")
    return LoginResponse(token=token["token"], expires_in=token["expires_in"], user=UserOut(**auth.public_user(user)))


@router.post("/login", response_model=LoginResponse)
def login(payload: LoginRequest, request: Request) -> LoginResponse:
    allowed, retry_after = _login_limiter.check(f"login:{auth.client_key(request)}")
    if not allowed:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "Too many login attempts. Try again shortly.",
            headers={"Retry-After": str(retry_after)},
        )
    user = auth.find_user_by_email(payload.email)
    if not user or not auth.verify_password(payload.password, user.get("password_hash", "")):
        db.audit("anonymous", "auth.login_failed", f"Failed login for {payload.email}")
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid email or password.")

    token = auth.create_token(user)
    db.audit(user, "auth.login", "Successful login")
    return LoginResponse(token=token["token"], expires_in=token["expires_in"], user=UserOut(**auth.public_user(user)))


@router.get("/me", response_model=UserOut)
def me(user: dict = Depends(auth.current_user)) -> UserOut:
    return UserOut(**auth.public_user(user))


@router.get("/demo-accounts")
def demo_accounts() -> dict:
    """Expose the seeded demo accounts only when seeding is enabled.

    Passwords are the documented development defaults; the endpoint exists so
    the login screen can offer one-click demo access. Disable by setting
    ``SEED_DEMO_USERS=0``.
    """
    if not config.SEED_DEMO_USERS:
        return {"accounts": []}
    return {
        "accounts": [
            {"email": config.SEED_ADMIN_EMAIL, "role": "admin", "password": config.SEED_ADMIN_PASSWORD},
            {"email": "analyst@promptshield.ai", "role": "analyst", "password": config.SEED_DEMO_PASSWORD},
            {"email": "viewer@promptshield.ai", "role": "viewer", "password": config.SEED_DEMO_PASSWORD},
        ],
        "note": "Development demo accounts. Change or disable them before production use.",
    }
