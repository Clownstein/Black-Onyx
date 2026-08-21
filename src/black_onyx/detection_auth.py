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
    explicit = os.environ.get("BLACK_ONYX_AA_JWT_SECRET", "").strip()
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
    tenant_id: str = "default",
    ttl_seconds: int = 900,
) -> str:
    """HS256 JWT compatible with incident-api / asset-registry tenant validation."""
    now = int(time.time())
    roles = ROLE_MAP.get(role, ["viewer"])
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
