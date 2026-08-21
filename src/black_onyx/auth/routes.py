"""Versioned authentication and administration API."""

from __future__ import annotations

import smtplib

from pydantic import BaseModel, EmailStr, Field
from fastapi import APIRouter, Depends, HTTPException, Request, Response

from black_onyx.auth.context import get_auth_service
from black_onyx.auth.dependencies import current_principal, require_admin
from black_onyx.auth.middleware import CSRF_COOKIE, session_cookie_name
from black_onyx.auth.service import AuthError, Principal, Role

router = APIRouter(prefix="/api/v1/auth", tags=["authentication"])
admin_router = APIRouter(prefix="/api/v1/admin", tags=["administration"])


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)
    mfa_code: str | None = Field(default=None, max_length=32)


class RegisterRequest(BaseModel):
    token: str = Field(min_length=20, max_length=256)
    display_name: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=12, max_length=128)


class InviteRequest(BaseModel):
    email: EmailStr
    role: Role
    send_email: bool = False


class MFAConfirm(BaseModel):
    code: str = Field(min_length=6, max_length=32)


class PasswordResetRequest(BaseModel):
    email: EmailStr


class PasswordResetConfirm(BaseModel):
    token: str = Field(min_length=20, max_length=256)
    password: str = Field(min_length=12, max_length=128)


class PasswordChangeRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=128)
    new_password: str = Field(min_length=12, max_length=128)


class MFADisableRequest(BaseModel):
    password: str = Field(min_length=1, max_length=128)
    code: str = Field(min_length=6, max_length=32)


class UserUpdateRequest(BaseModel):
    role: Role | None = None
    active: bool | None = None


def set_session_cookies(response: Response, session: str, csrf: str) -> None:
    config = get_auth_service().config
    response.set_cookie(
        session_cookie_name(config), session, httponly=True, secure=config.secure_cookies,
        samesite="lax", path="/",
    )
    response.set_cookie(
        CSRF_COOKIE, csrf, httponly=False, secure=config.secure_cookies,
        samesite="lax", path="/",
    )


@router.post("/login")
def login(payload: LoginRequest, request: Request, response: Response) -> dict:
    auth = get_auth_service()
    try:
        principal = auth.authenticate(
            str(payload.email), payload.password, payload.mfa_code,
            request.client.host if request.client else "",
        )
    except AuthError as exc:
        raise HTTPException(status_code=401, detail=str(exc))
    previous = request.cookies.get(session_cookie_name(auth.config), "")
    if previous:
        auth.delete_session(previous)
    session, csrf = auth.create_session(
        principal, request.client.host if request.client else "", request.headers.get("user-agent", "")
    )
    set_session_cookies(response, session, csrf)
    auth.audit(principal, "auth.login", ip=request.client.host if request.client else "")
    return {"user": principal.to_dict(), "csrf_token": csrf}


@router.post("/register")
def register(payload: RegisterRequest, request: Request, response: Response) -> dict:
    auth = get_auth_service()
    try:
        principal = auth.register(payload.token, payload.password, payload.display_name)
    except AuthError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    session, csrf = auth.create_session(
        principal, request.client.host if request.client else "", request.headers.get("user-agent", "")
    )
    set_session_cookies(response, session, csrf)
    auth.audit(principal, "auth.register")
    return {"user": principal.to_dict(), "csrf_token": csrf}


@router.post("/logout")
def logout(request: Request, response: Response, principal: Principal = Depends(current_principal)) -> dict:
    config = get_auth_service().config
    cookie_name = session_cookie_name(config)
    token = request.cookies.get(cookie_name, "")
    if token:
        get_auth_service().delete_session(token)
    response.delete_cookie(cookie_name, path="/")
    response.delete_cookie(CSRF_COOKIE, path="/")
    return {"status": "ok"}


@router.get("/me")
def me(principal: Principal = Depends(current_principal)) -> dict:
    return {"user": principal.to_dict()}


@router.post("/mfa/begin")
def begin_mfa(principal: Principal = Depends(current_principal)) -> dict:
    return {"provisioning_uri": get_auth_service().begin_mfa(principal)}


@router.post("/mfa/confirm")
def confirm_mfa(payload: MFAConfirm, principal: Principal = Depends(current_principal)) -> dict:
    try:
        codes = get_auth_service().enable_mfa(principal, payload.code)
    except AuthError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"recovery_codes": codes}


@router.post("/mfa/disable")
def disable_mfa(payload: MFADisableRequest, principal: Principal = Depends(current_principal)) -> dict:
    try:
        get_auth_service().disable_mfa(principal, payload.password, payload.code)
    except AuthError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"status": "ok"}


@router.post("/password/change")
def change_password(payload: PasswordChangeRequest, principal: Principal = Depends(current_principal)) -> dict:
    try:
        get_auth_service().change_password(principal, payload.current_password, payload.new_password)
    except AuthError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"status": "ok", "reauthentication_required": True}


@router.post("/password-reset/request")
def request_password_reset(payload: PasswordResetRequest, request: Request) -> dict:
    auth = get_auth_service()
    token, email = auth.request_password_reset(
        str(payload.email), request.client.host if request.client else ""
    )
    if token and email:
        link = f"{auth.config.external_url.rstrip('/')}/reset-password?token={token}"
        try:
            auth.send_link(email, "Black Onyx password reset", link)
        except (OSError, smtplib.SMTPException):
            pass
    return {"status": "ok", "message": "If the account exists, reset instructions have been sent."}


@router.post("/password-reset/confirm")
def confirm_password_reset(payload: PasswordResetConfirm) -> dict:
    try:
        get_auth_service().reset_password(payload.token, payload.password)
    except AuthError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"status": "ok"}


@admin_router.post("/invitations")
def create_invitation(payload: InviteRequest, principal: Principal = Depends(require_admin)) -> dict:
    auth = get_auth_service()
    token = auth.create_invitation(principal, str(payload.email), payload.role)
    link = f"{auth.config.external_url.rstrip('/')}/register?token={token}"
    delivered = auth.send_link(str(payload.email), "Your Black Onyx invitation", link) if payload.send_email else False
    return {"invitation_url": link, "email_delivered": delivered, "expires_in_hours": 24}


@admin_router.get("/users")
def list_users(principal: Principal = Depends(require_admin)) -> dict:
    rows = get_auth_service().db._conn.execute(
        "SELECT user_id,email,display_name,role,active,created_at,updated_at FROM users ORDER BY created_at"
    ).fetchall()
    return {"users": [dict(row) for row in rows]}


@admin_router.get("/invitations")
def list_invitations(principal: Principal = Depends(require_admin)) -> dict:
    rows = get_auth_service().db._conn.execute(
        "SELECT invitation_id,email,role,created_at,expires_at,used_at "
        "FROM invitations ORDER BY created_at DESC LIMIT 500"
    ).fetchall()
    return {"invitations": [dict(row) for row in rows]}


@admin_router.patch("/users/{user_id}")
def update_user(
    user_id: str, payload: UserUpdateRequest, principal: Principal = Depends(require_admin)
) -> dict:
    if payload.role is None and payload.active is None:
        raise HTTPException(status_code=422, detail="No changes supplied")
    try:
        get_auth_service().update_user(principal, user_id, payload.role, payload.active)
    except AuthError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"status": "ok"}


@admin_router.post("/users/{user_id}/password-reset")
def admin_password_reset(user_id: str, principal: Principal = Depends(require_admin)) -> dict:
    auth = get_auth_service()
    row = auth.db._conn.execute(
        "SELECT email,active FROM users WHERE user_id=?", (user_id,)
    ).fetchone()
    if not row or not row["active"]:
        raise HTTPException(status_code=404, detail="User not found")
    token = auth.create_password_reset(user_id)
    link = f"{auth.config.external_url.rstrip('/')}/reset-password?token={token}"
    auth.audit(principal, "password_reset.admin_create", "user", user_id)
    return {"reset_url": link, "expires_in_minutes": 30}
