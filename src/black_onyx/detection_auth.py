"""Mint short-lived JWTs for detection-plane APIs from Black Onyx sessions."""

from __future__ import annotations

import os
import time
from typing import Any

import jwt

from black_onyx.crypto import resolve_auth_secret

ROLE_MAP = {
    "admin": ["admin"],
    "analyst": ["analyst"],
    "viewer": ["viewer"],
}


def detection_jwt_secret() -> str:
    """Shared HS256 secret with incident-api (OIDC_HS_SECRET)."""
    explicit = os.environ.get("BLACK_ONYX_DETECTION_JWT_SECRET", "").strip()
    if explicit:
        return explicit
    explicit = os.environ.get("OIDC_HS_SECRET", "").strip()
    if explicit:
        return explicit
    return resolve_auth_secret(os.environ.get("BLACK_ONYX_AUTH_SECRET_ENV", "BLACK_ONYX_AUTH_SECRET"))


def mint_detection_token(
    *,
    subject: str,
    role: str,
    tenant_id: str,
    ttl_seconds: int = 900,
) -> str:
    """HS256 JWT compatible with incident-api / asset-registry tenant validation."""
    subject = str(subject or "").strip()
    tenant_id = str(tenant_id or "").strip()
    if not subject:
        raise ValueError("detection JWT subject is required")
    if not tenant_id:
        raise ValueError("detection JWT tenant_id is required")
    if role not in ROLE_MAP:
        raise ValueError("detection JWT role must be admin, analyst, or viewer")
    if ttl_seconds < 1 or ttl_seconds > 900:
        raise ValueError("detection JWT ttl_seconds must be between 1 and 900")
    now = int(time.time())
    roles = ROLE_MAP[role]
    payload: dict[str, Any] = {
        "sub": subject,
        "tenant_id": tenant_id,
        "tid": tenant_id,
        "roles": roles,
        "role": roles[0],
        "iat": now,
        "exp": now + ttl_seconds,
    }
    return jwt.encode(payload, detection_jwt_secret(), algorithm="HS256")
