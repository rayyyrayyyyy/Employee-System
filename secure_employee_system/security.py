import secrets
from datetime import datetime, timedelta
from typing import Any

from fastapi import Depends, HTTPException, Request, status
from passlib.context import CryptContext
from sqlalchemy.orm import Session
from starlette.responses import RedirectResponse

from database import get_db
from models import AuditLog, User
from validators import normalize_username


pwd_context = CryptContext(schemes=["argon2", "bcrypt"], deprecated="auto")
SESSION_USER_ID = "user_id"
CSRF_SESSION_KEY = "csrf_token"
LOGIN_ATTEMPTS: dict[str, dict[str, Any]] = {}
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_MINUTES = 10


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, password_hash: str) -> bool:
    return pwd_context.verify(plain_password, password_hash)


def get_client_ip(request: Request) -> str:
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()[:45]
    if request.client:
        return request.client.host[:45]
    return "unknown"


def add_audit_log(db: Session, user_id: int | None, action: str, ip_address: str, status_text: str) -> None:
    db.add(
        AuditLog(
            user_id=user_id,
            action=action,
            ip_address=ip_address,
            status=status_text,
        )
    )


def get_csrf_token(request: Request) -> str:
    token = request.session.get(CSRF_SESSION_KEY)
    if not token:
        token = secrets.token_urlsafe(32)
        request.session[CSRF_SESSION_KEY] = token
    return token


def validate_csrf_token(request: Request, submitted_token: str | None) -> None:
    expected_token = request.session.get(CSRF_SESSION_KEY)
    if not expected_token or not submitted_token or not secrets.compare_digest(expected_token, submitted_token):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid form token.")


def is_locked_out(username: str) -> bool:
    attempt = LOGIN_ATTEMPTS.get(normalize_username(username))
    if not attempt:
        return False
    locked_until = attempt.get("locked_until")
    if locked_until and datetime.utcnow() < locked_until:
        return True
    if locked_until and datetime.utcnow() >= locked_until:
        LOGIN_ATTEMPTS.pop(normalize_username(username), None)
    return False


def record_login_failure(username: str) -> None:
    normalized = normalize_username(username)
    attempt = LOGIN_ATTEMPTS.setdefault(normalized, {"count": 0, "locked_until": None})
    attempt["count"] += 1
    if attempt["count"] >= MAX_LOGIN_ATTEMPTS:
        attempt["locked_until"] = datetime.utcnow() + timedelta(minutes=LOCKOUT_MINUTES)


def clear_login_failures(username: str) -> None:
    LOGIN_ATTEMPTS.pop(normalize_username(username), None)


def get_current_user(request: Request, db: Session = Depends(get_db)) -> User:
    user_id = request.session.get(SESSION_USER_ID)
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Login required.")

    user = db.get(User, user_id)
    if not user or not user.is_active:
        request.session.clear()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Login required.")
    return user


def require_login(current_user: User = Depends(get_current_user)) -> User:
    return current_user


def require_admin(current_user: User = Depends(get_current_user)) -> User:
    if current_user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required.")
    return current_user


def require_employee(current_user: User = Depends(get_current_user)) -> User:
    if current_user.role != "employee":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Employee access required.")
    return current_user


def login_user(request: Request, user: User) -> None:
    request.session.clear()
    request.session[SESSION_USER_ID] = user.id
    get_csrf_token(request)


def logout_user(request: Request) -> None:
    request.session.clear()


def redirect_for_user(user: User) -> RedirectResponse:
    if user.role == "admin":
        return RedirectResponse(url="/admin/dashboard", status_code=status.HTTP_303_SEE_OTHER)
    return RedirectResponse(url="/employee/dashboard", status_code=status.HTTP_303_SEE_OTHER)
