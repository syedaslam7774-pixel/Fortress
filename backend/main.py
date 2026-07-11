
"""
================================================================================
 FORTRESS API — single-file backend (FastAPI + Supabase)
================================================================================
Everything lives in this one file, organized into clearly labeled sections
so you can Ctrl+F a banner like "SECTION 4" to jump straight to that part.

  SECTION 1  — Imports
  SECTION 2  — Configuration (reads environment variables)
  SECTION 3  — Database connection (Supabase)
  SECTION 4  — Security: password hashing + JWT tokens
  SECTION 5  — Small helpers: secure tokens, email/password validation
  SECTION 6  — Data shapes: roles + request/response schemas
  SECTION 7  — Services: email sending, audit logging, core auth logic
  SECTION 8  — Auth guard + role-based access control (RBAC) dependencies
  SECTION 9  — Routes: auth, user, admin endpoints
  SECTION 10 — App setup: middleware, rate limiting, error handling

--------------------------------------------------------------------------------
 WHY /api/register WAS RETURNING 500 BEFORE
--------------------------------------------------------------------------------
Your Vercel logs showed this app's own startup message getting cut off:
"...Supabase_url is r[equired]..." — that means SUPABASE_URL / SUPABASE_KEY
were never set as environment variables on the Vercel project, so the app
refused to talk to the database and every route failed.

FIX: In Vercel -> Project -> Settings -> Environment Variables, add every
variable in the list below for Production (and Preview, if used), then
REDEPLOY. Env vars only take effect on deployments made after you save them.

Required env vars:
    SUPABASE_URL              your Supabase project URL
    SUPABASE_KEY              Supabase service role or anon key
    JWT_ACCESS_PRIVATE_KEY    RSA private key (PEM), signs access tokens
    JWT_ACCESS_PUBLIC_KEY     RSA public key (PEM), verifies access tokens
    JWT_REFRESH_PRIVATE_KEY   RSA private key (PEM), signs refresh tokens
    JWT_REFRESH_PUBLIC_KEY    RSA public key (PEM), verifies refresh tokens
    FRONTEND_URL              used to build verification/reset links
    ALLOWED_ORIGINS           comma-separated CORS origins, or "*"

Generate each key pair once (locally, not on the server) with:
    openssl genrsa -out private.pem 2048
    openssl rsa -in private.pem -pubout -out public.pem
Then paste each PEM's contents into the matching env var with literal
"\n" in place of real newlines (Settings un-escapes them at load time).
Requires the "cryptography" package installed alongside python-jose,
since RS256 needs it as jose's crypto backend.

Optional (without these, emails are logged instead of actually sent):
    SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, EMAIL_FROM

Run schema.sql (see bottom of this file, in the comment block) in the
Supabase SQL editor once before your first deploy.
================================================================================
"""

# ============================================================================
# SECTION 1 — IMPORTS
# ============================================================================
import os
import re
import uuid
import hashlib
import secrets
import logging
import smtplib
from enum import Enum
from email.mime.text import MIMEText
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from typing import Optional

from fastapi import FastAPI, APIRouter, Depends, HTTPException, Request, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from fastapi.dependencies.utils import get_dependant
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, field_validator
from jose import jwt, JWTError
from passlib.context import CryptContext
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("fortress")


# ============================================================================
# SECTION 2 — CONFIGURATION  (reads all settings from environment variables)
# ============================================================================
class Settings:
    # --- Supabase ---
    SUPABASE_URL: str = os.environ.get("SUPABASE_URL", "")
    SUPABASE_KEY: str = os.environ.get("SUPABASE_KEY", "")

    # --- JWT (RS256: private key signs, public key verifies) ---
    # PEM values are read from env vars. Most hosts don't support real
    # newlines in env vars, so keys are stored with literal "\n" and
    # un-escaped here.
    JWT_ALGORITHM: str = os.environ.get("JWT_ALGORITHM", "RS256")
    JWT_ACCESS_PRIVATE_KEY: str = os.environ.get("JWT_ACCESS_PRIVATE_KEY", "").replace("\\n", "\n")
    JWT_ACCESS_PUBLIC_KEY: str = os.environ.get("JWT_ACCESS_PUBLIC_KEY", "").replace("\\n", "\n")
    JWT_REFRESH_PRIVATE_KEY: str = os.environ.get("JWT_REFRESH_PRIVATE_KEY", "").replace("\\n", "\n")
    JWT_REFRESH_PUBLIC_KEY: str = os.environ.get("JWT_REFRESH_PUBLIC_KEY", "").replace("\\n", "\n")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.environ.get("ACCESS_TOKEN_EXPIRE_MINUTES", "15"))
    REFRESH_TOKEN_EXPIRE_DAYS: int = int(os.environ.get("REFRESH_TOKEN_EXPIRE_DAYS", "30"))

    # --- Email (SMTP) ---
    SMTP_HOST: str = os.environ.get("SMTP_HOST", "")
    SMTP_PORT: int = int(os.environ.get("SMTP_PORT", "587"))
    SMTP_USER: str = os.environ.get("SMTP_USER", "")
    SMTP_PASSWORD: str = os.environ.get("SMTP_PASSWORD", "")
    EMAIL_FROM: str = os.environ.get("EMAIL_FROM", "no-reply@example.com")

    # --- App / links ---
    FRONTEND_URL: str = os.environ.get("FRONTEND_URL", "http://localhost:3000")
    ENV: str = os.environ.get("ENV", "production")

    # --- Rate limiting ---
    RATE_LIMIT_DEFAULT: str = os.environ.get("RATE_LIMIT_DEFAULT", "100/minute")
    RATE_LIMIT_AUTH: str = os.environ.get("RATE_LIMIT_AUTH", "5/minute")

    # --- CORS ---
    ALLOWED_ORIGINS: list = [
        o.strip() for o in os.environ.get("ALLOWED_ORIGINS", "*").split(",") if o.strip()
    ]

    def validate(self) -> list:
        """Return a list of human-readable problems with the current config."""
        problems = []
        if not self.SUPABASE_URL:
            problems.append("SUPABASE_URL is not set.")
        if not self.SUPABASE_KEY:
            problems.append("SUPABASE_KEY is not set.")
        if not self.JWT_ACCESS_PRIVATE_KEY:
            problems.append("JWT_ACCESS_PRIVATE_KEY is not set.")
        if not self.JWT_ACCESS_PUBLIC_KEY:
            problems.append("JWT_ACCESS_PUBLIC_KEY is not set.")
        if not self.JWT_REFRESH_PRIVATE_KEY:
            problems.append("JWT_REFRESH_PRIVATE_KEY is not set.")
        if not self.JWT_REFRESH_PUBLIC_KEY:
            problems.append("JWT_REFRESH_PUBLIC_KEY is not set.")
        return problems


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()


# ============================================================================
# SECTION 3 — DATABASE CONNECTION (Supabase)
# ============================================================================
# This fails "soft": if config is missing or the client can't start, we don't
# crash the whole app — we record init_error and every DB-dependent route
# returns a clear 503 with that message instead of a bare 500.
supabase = None
init_error: Optional[str] = None

_config_problems = settings.validate()
if _config_problems:
    init_error = "Configuration error(s): " + "; ".join(_config_problems)
else:
    try:
        from supabase import create_client, Client
        supabase: "Client" = create_client(settings.SUPABASE_URL, settings.SUPABASE_KEY)
    except Exception as e:  # noqa: BLE001
        init_error = f"Supabase client failed to initialize: {e}"


def get_db():
    """FastAPI dependency: yields the Supabase client, or raises a clear 503."""
    if init_error or supabase is None:
        raise HTTPException(status_code=503, detail=init_error or "Database unavailable.")
    return supabase


# ============================================================================
# SECTION 4 — SECURITY: password hashing + JWT access/refresh tokens
# ============================================================================
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def _encode_jwt(payload: dict, private_key: str, expires_delta: timedelta) -> str:
    """Sign with the RSA private key. Only holders of the private key can mint tokens."""
    to_encode = payload.copy()
    now = datetime.now(timezone.utc)
    to_encode.update({"iat": now, "exp": now + expires_delta, "jti": str(uuid.uuid4())})
    return jwt.encode(to_encode, private_key, algorithm=settings.JWT_ALGORITHM)


def create_access_token(subject: str, role: str) -> str:
    payload = {"sub": subject, "role": role, "type": "access"}
    return _encode_jwt(payload, settings.JWT_ACCESS_PRIVATE_KEY,
                        timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES))


def create_refresh_token(subject: str) -> str:
    payload = {"sub": subject, "type": "refresh"}
    return _encode_jwt(payload, settings.JWT_REFRESH_PRIVATE_KEY,
                        timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS))


def decode_access_token(token: str) -> dict:
    """Verify with the RSA public key. Anyone with the public key can verify, not mint."""
    payload = jwt.decode(token, settings.JWT_ACCESS_PUBLIC_KEY, algorithms=[settings.JWT_ALGORITHM])
    if payload.get("type") != "access":
        raise JWTError("Not an access token.")
    return payload


def decode_refresh_token(token: str) -> dict:
    payload = jwt.decode(token, settings.JWT_REFRESH_PUBLIC_KEY, algorithms=[settings.JWT_ALGORITHM])
    if payload.get("type") != "refresh":
        raise JWTError("Not a refresh token.")
    return payload


# ============================================================================
# SECTION 5 — SMALL HELPERS: secure one-time tokens, email/password checks
# ============================================================================
def generate_secure_token(n_bytes: int = 32) -> str:
    """Random URL-safe token, e.g. for email verification / password reset links."""
    return secrets.token_urlsafe(n_bytes)


def hash_token(token: str) -> str:
    """We only ever store the hash of one-time tokens, never the raw token."""
    return hashlib.sha256(token.encode()).hexdigest()


_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def is_valid_email(email: str) -> bool:
    return bool(_EMAIL_RE.match(email))


def password_strength_errors(password: str) -> list:
    """Return unmet requirements; empty list means the password is strong enough."""
    errors = []
    if len(password) < 10:
        errors.append("Password must be at least 10 characters.")
    if not re.search(r"[A-Z]", password):
        errors.append("Password must contain an uppercase letter.")
    if not re.search(r"[a-z]", password):
        errors.append("Password must contain a lowercase letter.")
    if not re.search(r"\d", password):
        errors.append("Password must contain a digit.")
    if not re.search(r"[^\w\s]", password):
        errors.append("Password must contain a symbol.")
    return errors


# ============================================================================
# SECTION 6 — DATA SHAPES: roles + request/response schemas
# ============================================================================
class Role(str, Enum):
    USER = "user"
    ADMIN = "admin"
    SUPERADMIN = "superadmin"


# ---- auth request/response schemas ----
class RegisterRequest(BaseModel):
    email: str
    password: str

    @field_validator("email")
    @classmethod
    def _check_email(cls, v):
        if not is_valid_email(v):
            raise ValueError("Invalid email address.")
        return v.lower().strip()

    @field_validator("password")
    @classmethod
    def _check_password(cls, v):
        errors = password_strength_errors(v)
        if errors:
            raise ValueError(" ".join(errors))
        return v


class LoginRequest(BaseModel):
    email: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class RefreshRequest(BaseModel):
    refresh_token: str


class LogoutRequest(BaseModel):
    refresh_token: str


class VerifyEmailRequest(BaseModel):
    token: str


class ForgotPasswordRequest(BaseModel):
    email: str


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str

    @field_validator("new_password")
    @classmethod
    def _check_password(cls, v):
        errors = password_strength_errors(v)
        if errors:
            raise ValueError(" ".join(errors))
        return v


# ---- user / admin schemas ----
class UserResponse(BaseModel):
    id: str
    email: str
    role: Role
    is_email_verified: bool
    is_active: bool


class UserRoleUpdate(BaseModel):
    role: Role


class UserActiveUpdate(BaseModel):
    is_active: bool


class PaginatedUsers(BaseModel):
    total: int
    page: int
    page_size: int
    items: list[UserResponse]


# ============================================================================
# SECTION 7 — SERVICES: email sending, audit logging, core auth logic
# ============================================================================

# ---- 7a. Email service -----------------------------------------------------
# If SMTP isn't configured (e.g. local dev), we log the email instead of
# sending it, so the rest of the flow can still be tested end to end.
def _send_email(to_email: str, subject: str, body: str) -> None:
    if not settings.SMTP_HOST or not settings.SMTP_USER:
        logger.warning("SMTP not configured. Would have sent to %s: %s\n%s", to_email, subject, body)
        return

    msg = MIMEText(body, "html")
    msg["Subject"] = subject
    msg["From"] = settings.EMAIL_FROM
    msg["To"] = to_email

    with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT) as server:
        server.starttls()
        server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
        server.sendmail(settings.EMAIL_FROM, [to_email], msg.as_string())


def send_verification_email(to_email: str, token: str) -> None:
    link = f"{settings.FRONTEND_URL}/verify-email?token={token}"
    _send_email(
        to_email, "Verify your email",
        f'<p>Welcome! Verify your email: <a href="{link}">{link}</a></p><p>Expires in 24 hours.</p>',
    )


def send_password_reset_email(to_email: str, token: str) -> None:
    link = f"{settings.FRONTEND_URL}/reset-password?token={token}"
    _send_email(
        to_email, "Reset your password",
        f'<p>Reset your password: <a href="{link}">{link}</a></p>'
        f"<p>If you didn't request this, ignore this email. Expires in 1 hour.</p>",
    )


# ---- 7b. Audit logging ------------------------------------------------------
# Never allowed to break the calling request — a logging failure should never
# be why a login or registration fails.
def log_action(db, user_id: Optional[str], action: str, details: Optional[dict] = None,
                ip_address: Optional[str] = None) -> None:
    try:
        db.table("audit_logs").insert({
            "user_id": user_id, "action": action, "details": details or {}, "ip_address": ip_address,
        }).execute()
    except Exception as e:  # noqa: BLE001
        logger.error("Failed to write audit log for action=%s user_id=%s: %s", action, user_id, e)


# ---- 7c. Core auth logic (registration, login, tokens, resets) -------------
EMAIL_VERIFICATION_TTL_HOURS = 24
PASSWORD_RESET_TTL_HOURS = 1


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _get_user_by_email(db, email: str):
    result = db.table("users").select("*").eq("email", email).execute()
    return result.data[0] if result.data else None


def _get_user_by_id(db, user_id: str):
    result = db.table("users").select("*").eq("id", user_id).execute()
    return result.data[0] if result.data else None


def register_user(db, email: str, password: str, ip_address: Optional[str] = None) -> dict:
    """Create a new user account and send an email verification link."""
    if _get_user_by_email(db, email):
        # Generic message avoids leaking which emails are already registered.
        raise HTTPException(status_code=409, detail="Unable to register with these details.")

    user_row = db.table("users").insert({
        "email": email, "password_hash": hash_password(password),
        "role": Role.USER.value, "is_email_verified": False, "is_active": True,
    }).execute()
    user = user_row.data[0]

    token = generate_secure_token()
    db.table("email_verification_tokens").insert({
        "user_id": user["id"], "token_hash": hash_token(token),
        "expires_at": (_now_utc() + timedelta(hours=EMAIL_VERIFICATION_TTL_HOURS)).isoformat(),
    }).execute()
    send_verification_email(email, token)

    log_action(db, user["id"], "user.register", ip_address=ip_address)
    return user


def verify_email(db, token: str) -> None:
    """Mark a user's email as verified using a one-time token."""
    token_hash = hash_token(token)
    result = db.table("email_verification_tokens").select("*").eq("token_hash", token_hash).execute()
    if not result.data:
        raise HTTPException(status_code=400, detail="Invalid or expired verification token.")

    record = result.data[0]
    if _now_utc() > datetime.fromisoformat(record["expires_at"]):
        raise HTTPException(status_code=400, detail="Invalid or expired verification token.")

    db.table("users").update({"is_email_verified": True}).eq("id", record["user_id"]).execute()
    db.table("email_verification_tokens").delete().eq("id", record["id"]).execute()
    log_action(db, record["user_id"], "user.email_verified")


def _issue_tokens(db, user: dict, user_agent: Optional[str], ip_address: Optional[str]) -> dict:
    """Create a fresh access+refresh token pair and record the session (hashed) in the DB."""
    access_token = create_access_token(subject=user["id"], role=user["role"])
    refresh_token = create_refresh_token(subject=user["id"])

    db.table("sessions").insert({
        "user_id": user["id"], "refresh_token_hash": hash_token(refresh_token),
        "user_agent": user_agent, "ip_address": ip_address, "revoked": False,
        "expires_at": (_now_utc() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)).isoformat(),
    }).execute()

    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}


def authenticate_user(db, email: str, password: str, user_agent: Optional[str] = None,
                       ip_address: Optional[str] = None) -> dict:
    """Verify credentials and issue a token pair on success."""
    user = _get_user_by_email(db, email)
    if not user or not verify_password(password, user["password_hash"]):
        log_action(db, user["id"] if user else None, "auth.login_failed", ip_address=ip_address)
        raise HTTPException(status_code=401, detail="Incorrect email or password.")

    if not user["is_active"]:
        raise HTTPException(status_code=403, detail="This account has been deactivated.")

    tokens = _issue_tokens(db, user, user_agent, ip_address)
    log_action(db, user["id"], "auth.login", ip_address=ip_address)
    return tokens


def refresh_tokens(db, refresh_token: str, user_agent: Optional[str] = None,
                    ip_address: Optional[str] = None) -> dict:
    """Rotate a refresh token: revoke the old one, issue a brand new pair."""
    try:
        payload = decode_refresh_token(refresh_token)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid refresh token.")

    token_hash = hash_token(refresh_token)
    result = db.table("sessions").select("*").eq("refresh_token_hash", token_hash).execute()
    if not result.data:
        raise HTTPException(status_code=401, detail="Session not found. Please log in again.")

    session = result.data[0]
    if session["revoked"]:
        raise HTTPException(status_code=401, detail="Session has been revoked. Please log in again.")
    if _now_utc() > datetime.fromisoformat(session["expires_at"]):
        raise HTTPException(status_code=401, detail="Session expired. Please log in again.")

    user = _get_user_by_id(db, payload["sub"])
    if not user or not user["is_active"]:
        raise HTTPException(status_code=401, detail="Account unavailable.")

    db.table("sessions").update({"revoked": True}).eq("id", session["id"]).execute()
    return _issue_tokens(db, user, user_agent, ip_address)


def logout_user(db, refresh_token: str) -> None:
    """Revoke a single session (this device only)."""
    token_hash = hash_token(refresh_token)
    db.table("sessions").update({"revoked": True}).eq("refresh_token_hash", token_hash).execute()


def request_password_reset(db, email: str, ip_address: Optional[str] = None) -> None:
    """Send a password reset link if the email exists. Silent no-op otherwise (no email enumeration)."""
    user = _get_user_by_email(db, email)
    if not user:
        return

    token = generate_secure_token()
    db.table("password_reset_tokens").insert({
        "user_id": user["id"], "token_hash": hash_token(token),
        "expires_at": (_now_utc() + timedelta(hours=PASSWORD_RESET_TTL_HOURS)).isoformat(), "used": False,
    }).execute()
    send_password_reset_email(email, token)
    log_action(db, user["id"], "auth.password_reset_requested", ip_address=ip_address)


def reset_password(db, token: str, new_password: str) -> None:
    """Consume a reset token, set the new password, and log out all other sessions."""
    token_hash = hash_token(token)
    result = db.table("password_reset_tokens").select("*").eq("token_hash", token_hash).execute()
    if not result.data:
        raise HTTPException(status_code=400, detail="Invalid or expired reset token.")

    record = result.data[0]
    if record["used"] or _now_utc() > datetime.fromisoformat(record["expires_at"]):
        raise HTTPException(status_code=400, detail="Invalid or expired reset token.")

    db.table("users").update({"password_hash": hash_password(new_password)}).eq("id", record["user_id"]).execute()
    db.table("password_reset_tokens").update({"used": True}).eq("id", record["id"]).execute()
    # A password reset invalidates every existing session, everywhere.
    db.table("sessions").update({"revoked": True}).eq("user_id", record["user_id"]).execute()
    log_action(db, record["user_id"], "auth.password_reset_completed")


# ============================================================================
# SECTION 8 — AUTH GUARD + ROLE-BASED ACCESS CONTROL (RBAC)
# ============================================================================
bearer_scheme = HTTPBearer(auto_error=False)


def get_client_ip(request: Request) -> Optional[str]:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else None


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db=Depends(get_db),
) -> dict:
    """Decode the bearer token and load the corresponding, active user."""
    if credentials is None:
        raise HTTPException(status_code=401, detail="Not authenticated.")

    try:
        payload = decode_access_token(credentials.credentials)
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token.")

    result = db.table("users").select("*").eq("id", payload["sub"]).execute()
    if not result.data:
        raise HTTPException(status_code=401, detail="User no longer exists.")

    user = result.data[0]
    if not user["is_active"]:
        raise HTTPException(status_code=403, detail="This account has been deactivated.")
    return user


def require_role(*allowed_roles: Role):
    """Dependency factory for RBAC, e.g. Depends(require_role(Role.ADMIN))."""

    def _check(user: dict = Depends(get_current_user)) -> dict:
        if user["role"] not in [r.value for r in allowed_roles]:
            raise HTTPException(status_code=403, detail="You do not have permission to do that.")
        return user

    return _check


# ============================================================================
# SECTION 9 — ROUTES
# ============================================================================

# ---- 9a. Auth routes: register, login, refresh, logout, verify, reset -----
auth_router = APIRouter(prefix="/api/auth", tags=["auth"])


@auth_router.post("/register", response_model=UserResponse, status_code=201)
def route_register(data: RegisterRequest, request: Request, db=Depends(get_db)):
    return register_user(db, data.email, data.password, ip_address=get_client_ip(request))


@auth_router.post("/login", response_model=TokenResponse)
def route_login(data: LoginRequest, request: Request, db=Depends(get_db)):
    return authenticate_user(db, data.email, data.password,
                              user_agent=request.headers.get("user-agent"), ip_address=get_client_ip(request))


@auth_router.post("/refresh", response_model=TokenResponse)
def route_refresh(data: RefreshRequest, request: Request, db=Depends(get_db)):
    return refresh_tokens(db, data.refresh_token,
                           user_agent=request.headers.get("user-agent"), ip_address=get_client_ip(request))


@auth_router.post("/logout", status_code=204)
def route_logout(data: LogoutRequest, request: Request, db=Depends(get_db)):
    logout_user(db, data.refresh_token)
    return None


@auth_router.post("/verify-email", status_code=204)
def route_verify_email(data: VerifyEmailRequest, request: Request, db=Depends(get_db)):
    verify_email(db, data.token)
    return None


@auth_router.post("/forgot-password", status_code=204)
def route_forgot_password(data: ForgotPasswordRequest, request: Request, db=Depends(get_db)):
    request_password_reset(db, data.email, ip_address=get_client_ip(request))
    return None


@auth_router.post("/reset-password", status_code=204)
def route_reset_password(data: ResetPasswordRequest, request: Request, db=Depends(get_db)):
    reset_password(db, data.token, data.new_password)
    return None


# ---- 9b. User routes: the currently logged-in user -------------------------
user_router = APIRouter(prefix="/api/user", tags=["user"])


@user_router.get("/me", response_model=UserResponse)
def route_get_me(user: dict = Depends(get_current_user)):
    return user


# ---- 9c. Admin routes: user management, protected by RBAC ------------------
admin_router = APIRouter(prefix="/api/admin", tags=["admin"])
_admin_only = require_role(Role.ADMIN, Role.SUPERADMIN)


@admin_router.get("/users", response_model=PaginatedUsers)
def route_list_users(page: int = Query(1, ge=1), page_size: int = Query(25, ge=1, le=100),
                      db=Depends(get_db), _admin: dict = Depends(_admin_only)):
    start = (page - 1) * page_size
    end = start + page_size - 1
    result = db.table("users").select("*", count="exact").range(start, end).execute()
    return {"total": result.count or 0, "page": page, "page_size": page_size, "items": result.data}


@admin_router.patch("/users/{user_id}/role", response_model=UserResponse)
def route_update_role(user_id: str, data: UserRoleUpdate, request: Request,
                       db=Depends(get_db), admin: dict = Depends(_admin_only)):
    if data.role == Role.SUPERADMIN and admin["role"] != Role.SUPERADMIN.value:
        raise HTTPException(status_code=403, detail="Only a superadmin can grant the superadmin role.")

    result = db.table("users").update({"role": data.role.value}).eq("id", user_id).execute()
    if not result.data:
        raise HTTPException(status_code=404, detail="User not found.")

    log_action(db, admin["id"], "admin.role_updated",
               details={"target_user": user_id, "new_role": data.role.value}, ip_address=get_client_ip(request))
    return result.data[0]


@admin_router.patch("/users/{user_id}/active", response_model=UserResponse)
def route_update_active(user_id: str, data: UserActiveUpdate, request: Request,
                         db=Depends(get_db), admin: dict = Depends(_admin_only)):
    result = db.table("users").update({"is_active": data.is_active}).eq("id", user_id).execute()
    if not result.data:
        raise HTTPException(status_code=404, detail="User not found.")

    action = "admin.user_activated" if data.is_active else "admin.user_deactivated"
    log_action(db, admin["id"], action, details={"target_user": user_id}, ip_address=get_client_ip(request))
    return result.data[0]


# ============================================================================
# SECTION 10 — APP SETUP: middleware, rate limiting, error handling
# ============================================================================
limiter = Limiter(key_func=get_remote_address, default_limits=[settings.RATE_LIMIT_DEFAULT])

app = FastAPI(title="Fortress API", version="1.0.0")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# --- CORS ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --- Security headers on every response ---
@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    if settings.ENV == "production":
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    return response


# --- Global error handling: never leak stack traces to the client ---
@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled error on %s %s", request.method, request.url.path)
    return JSONResponse(status_code=500, content={"detail": "Internal server error."})


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})


# --- Tighter rate limit on auth endpoints (credential stuffing protection) ---
# NOTE: limiter.shared_limit(...) returns a plain decorator function, not a
# Depends(...) object — it cannot be appended to route.dependencies (that
# list must only contain Depends instances, each with a .dependency
# attribute). Doing so crashed route registration at startup with:
#   AttributeError: 'function' object has no attribute 'dependency'
# Fix: wrap each endpoint's callable directly and rebuild its dependant.
for _route in auth_router.routes:
    if isinstance(_route, APIRoute):
        _route.endpoint = limiter.shared_limit(settings.RATE_LIMIT_AUTH, scope="auth")(_route.endpoint)
        _route.dependant = get_dependant(path=_route.path_format, call=_route.endpoint)

app.include_router(auth_router)
app.include_router(user_router)
app.include_router(admin_router)


# --- Health / status endpoints ---
@app.get("/")
def root():
    """Shows whether the app started cleanly. If init_error is set, check your env vars."""
    return {"status": "degraded" if init_error else "running", "init_error": init_error}


@app.get("/health")
def health():
    if init_error:
        raise HTTPException(status_code=503, detail=init_error)
    return {"status": "ok"}


# ============================================================================
# SUPABASE SQL SCHEMA — run this once in the Supabase SQL editor
# ============================================================================
"""
create extension if not exists "pgcrypto";

create table if not exists users (
    id uuid primary key default gen_random_uuid(),
    email text unique not null,
    password_hash text not null,
    role text not null default 'user' check (role in ('user', 'admin', 'superadmin')),
    is_email_verified boolean not null default false,
    is_active boolean not null default true,
    created_at timestamptz not null default now()
);

create table if not exists sessions (
    id uuid primary key default gen_random_uuid(),
    user_id uuid not null references users(id) on delete cascade,
    refresh_token_hash text not null unique,
    user_agent text,
    ip_address text,
    revoked boolean not null default false,
    expires_at timestamptz not null,
    created_at timestamptz not null default now()
);

create table if not exists email_verification_tokens (
    id uuid primary key default gen_random_uuid(),
    user_id uuid not null references users(id) on delete cascade,
    token_hash text not null unique,
    expires_at timestamptz not null,
    created_at timestamptz not null default now()
);

create table if not exists password_reset_tokens (
    id uuid primary key default gen_random_uuid(),
    user_id uuid not null references users(id) on delete cascade,
    token_hash text not null unique,
    used boolean not null default false,
    expires_at timestamptz not null,
    created_at timestamptz not null default now()
);

create table if not exists audit_logs (
    id uuid primary key default gen_random_uuid(),
    user_id uuid references users(id) on delete set null,
    action text not null,
    details jsonb default '{}',
    ip_address text,
    created_at timestamptz not null default now()
);

create index if not exists idx_sessions_user_id on sessions(user_id);
create index if not exists idx_audit_logs_user_id on audit_logs(user_id);
"""
