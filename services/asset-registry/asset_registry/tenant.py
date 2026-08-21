"""Tenant auth, optional OIDC JWT validation, and RBAC roles (parity with incident-api)."""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Annotated, Callable

import jwt
from fastapi import Depends, Header, HTTPException

from asset_registry.config import settings

ROLE_ORDER = ("viewer", "analyst", "ml", "admin")
# Auditor is read-only assessor access (same rank as viewer). Kept in parity
# with incident_api.tenant.ROLE_ALIASES — update both together.
ROLE_ALIASES = {"auditor": "viewer"}


def _constant_time_eq(provided: str | None, expected: str) -> bool:
    if not provided or not expected:
        return False
    return secrets.compare_digest(provided, expected)


@dataclass
class Principal:
    tenant_id: str
    subject: str = "anonymous"
    roles: set[str] = field(default_factory=lambda: {"viewer"})
    is_service: bool = False

    def has_at_least(self, minimum: str) -> bool:
        want = ROLE_ALIASES.get(minimum.lower(), minimum.lower())
        if want not in ROLE_ORDER:
            return False
        if self.is_service:
            return True
        have_ranks = [
            ROLE_ORDER.index(ROLE_ALIASES.get(r, r))
            for r in self.roles
            if ROLE_ALIASES.get(r, r) in ROLE_ORDER
        ]
        if not have_ranks:
            return False
        return max(have_ranks) >= ROLE_ORDER.index(want)


def _normalize_roles(raw: object) -> set[str]:
    roles: set[str] = set()
    if isinstance(raw, list):
        roles.update(str(r).lower() for r in raw)
    elif isinstance(raw, str) and raw.strip():
        roles.update(part.strip().lower() for part in raw.split(",") if part.strip())
    allowed = set(ROLE_ORDER) | set(ROLE_ALIASES)
    return {r for r in roles if r in allowed}


@lru_cache(maxsize=4)
def _jwks_client(jwks_url: str) -> jwt.PyJWKClient:
    return jwt.PyJWKClient(jwks_url)


def _decode_bearer(token: str) -> dict:
    try:
        if settings.oidc_hs_secret:
            return jwt.decode(
                token,
                settings.oidc_hs_secret,
                algorithms=["HS256"],
                audience=settings.oidc_audience or None,
                issuer=settings.oidc_issuer or None,
                options={"require": ["exp", "sub"]},
            )
        if not settings.oidc_jwks_url:
            raise HTTPException(
                status_code=503,
                detail="OIDC enabled but neither OIDC_HS_SECRET nor OIDC_JWKS_URL is configured",
            )
        signing_key = _jwks_client(settings.oidc_jwks_url).get_signing_key_from_jwt(token)
        return jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256", "ES256"],
            audience=settings.oidc_audience or None,
            issuer=settings.oidc_issuer or None,
            options={"require": ["exp", "sub"]},
        )
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=401, detail=f"invalid bearer token: {exc}") from exc


def require_principal(
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-Id"),
    authorization: str | None = Header(default=None),
    x_service_key: str | None = Header(default=None, alias="X-Service-Key"),
    x_role: str | None = Header(default=None, alias="X-Role"),
) -> Principal:
    """Resolve caller identity.

    Dev mode (OIDC_DISABLED=true): tenant header required; optional X-Role for RBAC tests.
    Prod mode: Bearer JWT required unless a valid X-Service-Key is presented.
    """
    if not x_tenant_id or not x_tenant_id.strip():
        raise HTTPException(status_code=400, detail="X-Tenant-Id header is required")
    tenant_id = x_tenant_id.strip()

    if settings.service_api_key and _constant_time_eq(x_service_key, settings.service_api_key):
        return Principal(
            tenant_id=tenant_id,
            subject="service",
            roles={"admin"},
            is_service=True,
        )

    if (
        authorization
        and authorization.lower().startswith("bearer ")
        and (settings.oidc_hs_secret or settings.oidc_issuer)
    ):
        token = authorization.split(" ", 1)[1].strip()
        claims = _decode_bearer(token)
        claim_tenant = claims.get("tenant_id") or claims.get("tid")
        if claim_tenant and str(claim_tenant) != tenant_id:
            raise HTTPException(status_code=403, detail="token tenant does not match X-Tenant-Id")
        roles = _normalize_roles(claims.get("roles"))
        realm = claims.get("realm_access")
        if isinstance(realm, dict):
            roles |= _normalize_roles(realm.get("roles"))
        if not roles:
            roles = {"viewer"}
        return Principal(
            tenant_id=tenant_id,
            subject=str(claims.get("sub") or "unknown"),
            roles=roles,
        )

    if settings.oidc_disabled:
        roles = _normalize_roles(x_role) or {"viewer"}
        if authorization and not authorization.lower().startswith("bearer "):
            raise HTTPException(status_code=401, detail="invalid authorization header")
        return Principal(tenant_id=tenant_id, subject="dev-user", roles=roles)

    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Bearer token required")
    if not settings.oidc_issuer and not settings.oidc_hs_secret:
        raise HTTPException(
            status_code=503,
            detail="OIDC is enabled but OIDC_ISSUER/OIDC_HS_SECRET are not configured",
        )

    token = authorization.split(" ", 1)[1].strip()
    claims = _decode_bearer(token)
    claim_tenant = claims.get("tenant_id") or claims.get("tid")
    if claim_tenant and str(claim_tenant) != tenant_id:
        raise HTTPException(status_code=403, detail="token tenant does not match X-Tenant-Id")

    roles = _normalize_roles(claims.get("roles"))
    realm = claims.get("realm_access")
    if isinstance(realm, dict):
        roles |= _normalize_roles(realm.get("roles"))
    if not roles:
        roles = {"viewer"}
    return Principal(
        tenant_id=tenant_id,
        subject=str(claims.get("sub") or "unknown"),
        roles=roles,
    )


def require_tenant(
    principal: Annotated[Principal, Depends(require_principal)],
) -> str:
    """Backward-compatible tenant dependency used by existing routers."""
    return principal.tenant_id


def require_role(minimum: str) -> Callable[..., Principal]:
    def _dep(principal: Annotated[Principal, Depends(require_principal)]) -> Principal:
        if not principal.has_at_least(minimum):
            raise HTTPException(
                status_code=403,
                detail=f"requires role {minimum} or higher; have {sorted(principal.roles)}",
            )
        return principal

    return _dep
