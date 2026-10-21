"""BFF proxy: Black Onyx session → security tooling backend (model-tools).

Mirrors routes_detection.py: session principal → derived bearer token →
upstream security-gateway. The browser never sees the security-gateway
directly all calls go through /api/v1/security/* on this BFF.

Routes:
  GET  /api/v1/security/health BFF health (viewer+)
  GET  /api/v1/security/capabilities tool availability (viewer+)
  POST /api/v1/security/tools/{path} execute a tool (analyst+)
  POST /api/v1/security/agent/run agent run (analyst+)
  GET  /api/v1/security/agent/runs/{id} paused agent run status (analyst+)
  POST /api/v1/security/agent/runs/{id}/resume resume with approval or denial
  POST /api/v1/security/chat/completions chat completions (analyst+)
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import re
import time
from typing import Any
from urllib.parse import unquote

import httpx
from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from black_onyx.audit.security_audit import SecurityAuditLogger
from black_onyx.auth.dependencies import current_principal, require_analyst, require_viewer
from black_onyx.auth.service import Principal, Role

logger = logging.getLogger(__name__)

security_router = APIRouter(tags=["security"])

_audit = SecurityAuditLogger()

SECURITY_GATEWAY_URL = os.environ.get(
    "BLACK_ONYX_SECURITY_GATEWAY_URL", "http://security-gateway:8000"
)
MAX_PROXY_BODY_BYTES = 16 * 1024 * 1024
MAX_PROXY_RESPONSE_BYTES = 32 * 1024 * 1024
# Tool runs may take up to 300s; keep headroom for runner startup and cleanup.
_PROXY_TIMEOUT_S = 360.0

# Token rotation window: the derived token changes every 15 minutes so a
# leaked value has bounded utility.
_TOKEN_WINDOW_S = 900


class InternalCaseIOCRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    ioc_type: str = Field(min_length=1, max_length=32, pattern=r"^[a-z][a-z0-9_-]{0,31}$")
    ioc_value: str = Field(min_length=1, max_length=4096)


def _verified_security_assertion(authorization: str | None) -> dict[str, Any]:
    """Verify the BFF-issued actor assertion for gateway callbacks."""
    secret = os.environ.get("SECURITY_GATEWAY_KEY", "")
    if len(secret) < 32 or not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid security assertion")
    token = authorization[7:]
    if len(token) > 4096 or token.count(".") != 1:
        raise HTTPException(status_code=401, detail="Invalid security assertion")
    payload, encoded_signature = token.split(".", 1)
    try:
        signature = base64.urlsafe_b64decode(encoded_signature + "=" * (-len(encoded_signature) % 4))
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    except (ValueError, json.JSONDecodeError):
        raise HTTPException(status_code=401, detail="Invalid security assertion") from None
    expected = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).digest()
    now = int(time.time())
    if (
        not hmac.compare_digest(signature, expected)
        or not isinstance(claims, dict)
        or claims.get("iss") != "black-onyx-bff"
        or claims.get("aud") != "black-onyx-security-gateway"
        or not isinstance(claims.get("sub"), str)
        or not claims["sub"]
        or claims.get("role") not in {"admin", "analyst"}
        or not isinstance(claims.get("iat"), int)
        or isinstance(claims.get("iat"), bool)
        or not isinstance(claims.get("exp"), int)
        or isinstance(claims.get("exp"), bool)
        or claims["iat"] > now + 30
        or claims["exp"] <= now
        or claims["exp"] - claims["iat"] > _TOKEN_WINDOW_S
    ):
        raise HTTPException(status_code=401, detail="Invalid security assertion")
    return claims


def _security_token(user: Principal) -> str:
    """Mint a gateway-scoped assertion with a stable actor identity."""
    secret = os.environ.get("SECURITY_GATEWAY_KEY", "")
    if len(secret) < 32:
        raise HTTPException(status_code=503, detail="Security gateway signing key is not configured")
    now = int(time.time())
    claims = {
        "iss": "black-onyx-bff", "aud": "black-onyx-security-gateway",
        "sub": user.user_id, "role": user.role.value,
        "iat": now, "exp": now + _TOKEN_WINDOW_S,
    }
    payload = base64.urlsafe_b64encode(
        json.dumps(claims, separators=(",", ":"), sort_keys=True).encode()
    ).rstrip(b"=")
    signature = hmac.new(secret.encode(), payload, hashlib.sha256).digest()
    return f"{payload.decode()}.{base64.urlsafe_b64encode(signature).rstrip(b'=').decode()}"


def _require_security_access(
    request: Request, user: Principal = Depends(current_principal)
) -> Principal:
    """Viewers may read; mutations require analyst/admin (Black Onyx roles)."""
    if request.method.upper() in {"GET", "HEAD", "OPTIONS"}:
        if user.role not in (Role.ADMIN, Role.ANALYST, Role.VIEWER):
            raise HTTPException(status_code=403, detail="Insufficient permission")
        return user
    if user.role not in (Role.ADMIN, Role.ANALYST):
        raise HTTPException(status_code=403, detail="Insufficient permission")
    return user


async def _proxy_security(
    request: Request,
    *,
    path: str,
    user: Principal,
) -> Response:
    """Forward a request to the security-gateway with principal auth."""
    decoded = unquote(path).replace("\\", "/")
    relative = decoded.lstrip("/")
    if (
        not relative
        or "//" in relative
        or any(
            part in {".", ".."} or any(ord(char) < 32 for char in part)
            for part in relative.split("/")
        )
    ):
        raise HTTPException(status_code=400, detail="Invalid security proxy path")

    url = f"{SECURITY_GATEWAY_URL.rstrip('/')}/{relative}"
    if request.url.query:
        url = f"{url}?{request.url.query}"

    headers = {
        "Authorization": f"Bearer {_security_token(user)}",
        "X-Principal": user.user_id,
        "X-Role": user.role.value,
        "Accept": request.headers.get("accept", "application/json"),
        "Content-Type": request.headers.get("content-type", "application/json"),
    }

    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > MAX_PROXY_BODY_BYTES:
                raise HTTPException(
                    status_code=413, detail="Security proxy body is too large"
                )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Invalid Content-Length") from exc

    raw_body = await request.body()
    if len(raw_body) > MAX_PROXY_BODY_BYTES:
        raise HTTPException(status_code=413, detail="Security proxy body is too large")

    import time as _time

    _started = _time.monotonic()
    _audit.log_tool_call(relative, {"method": request.method}, user.user_id)
    try:
        async with httpx.AsyncClient(
            timeout=_PROXY_TIMEOUT_S, trust_env=False, follow_redirects=False
        ) as client:
            async with client.stream(
                request.method, url, content=raw_body or None, headers=headers
            ) as upstream:
                upstream_length = upstream.headers.get("content-length")
                if upstream_length:
                    try:
                        if int(upstream_length) > MAX_PROXY_RESPONSE_BYTES:
                            return JSONResponse(
                                status_code=502,
                                content={
                                    "detail": "Security upstream response is too large"
                                },
                            )
                    except ValueError:
                        return JSONResponse(
                            status_code=502,
                            content={
                                "detail": "Security upstream returned an invalid Content-Length"
                            },
                        )
                chunks: list[bytes] = []
                response_bytes = 0
                async for chunk in upstream.aiter_bytes():
                    response_bytes += len(chunk)
                    if response_bytes > MAX_PROXY_RESPONSE_BYTES:
                        return JSONResponse(
                            status_code=502,
                            content={
                                "detail": "Security upstream response is too large"
                            },
                        )
                    chunks.append(chunk)
                body = b"".join(chunks)
                response_headers = {
                    k: v
                    for k, v in upstream.headers.items()
                    if k.lower() not in {"content-encoding", "transfer-encoding", "connection", "content-length"}
                }
                _audit.log_tool_result(
                    relative,
                    "success" if upstream.status_code < 400 else "error",
                    _time.monotonic() - _started,
                    status_code=upstream.status_code,
                    principal=user.user_id,
                )
                return Response(
                    content=body,
                    status_code=upstream.status_code,
                    headers=response_headers,
                )
    except httpx.HTTPError as exc:
        _audit.log_tool_result(
            relative, "error", _time.monotonic() - _started,
            error=type(exc).__name__, principal=user.user_id,
        )
        logger.warning(
            "Security upstream unavailable (%s): %s", path, type(exc).__name__
        )
        return JSONResponse(
            status_code=502,
            content={
                "detail": f"Security upstream unavailable: {type(exc).__name__}"
            },
        )


def _allow_public_targets_effective() -> bool:
    from black_onyx.api.service import get_service
    from black_onyx.settings_registry import deployment_entries

    desired = get_service().deployment_controller.desired_env("compose")
    for entry in deployment_entries(desired):
        if entry.key == "ALLOW_PUBLIC_TARGETS":
            return str(entry.effective or "false").lower() in ("1", "true", "yes")
    return False


@security_router.get("/api/v1/security/health")
async def security_bff_health(
    user: Principal = Depends(require_viewer),
) -> dict[str, Any]:
    """BFF health for the browser never expose internal gateway hostnames."""
    return {
        "status": "ok",
        "gateway_configured": bool((SECURITY_GATEWAY_URL or "").strip()),
        "allow_public_targets": _allow_public_targets_effective(),
        "user": user.email,
    }


@security_router.get("/api/v1/security/capabilities")
async def security_capabilities(
    request: Request,
    user: Principal = Depends(require_viewer),
) -> Response:
    """Tool availability matrix proxied to gateway /health/tools (viewer+)."""
    return await _proxy_security(request, path="health/tools", user=user)


@security_router.post("/api/v1/security/internal/cases/{case_id}/iocs")
async def security_internal_add_case_ioc(
    case_id: str,
    req: InternalCaseIOCRequest,
    authorization: str | None = Header(None),
) -> dict[str, str]:
    """Actor-bound gateway callback into the authoritative TIP case store."""
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", case_id):
        raise HTTPException(status_code=400, detail="Invalid case id")
    claims = _verified_security_assertion(authorization)
    from black_onyx.api.service import get_service

    case_manager = get_service().case_manager
    if not case_manager.get_case(case_id):
        raise HTTPException(status_code=404, detail="Case not found")
    args = {"case_id": case_id, "ioc_type": req.ioc_type, "ioc_value": req.ioc_value}
    _audit.log_tool_call("add_ioc_to_case", args, claims["sub"], source="security-gateway")
    case_manager.add_ioc_to_case(case_id, req.ioc_type, req.ioc_value)
    _audit.log_tool_result("add_ioc_to_case", "success", 0.0, principal=claims["sub"])
    return {"status": "ok"}


@security_router.api_route(
    "/api/v1/security/tools/{path:path}", methods=["GET", "POST"]
)
async def proxy_tools(
    path: str,
    request: Request,
    user: Principal = Depends(_require_security_access),
) -> Response:
    """Tool listing and execution proxied to gateway /v1/tools/* (analyst+ for POST)."""
    return await _proxy_security(request, path=f"v1/tools/{path}", user=user)


@security_router.post("/api/v1/security/agent/run")
async def proxy_agent_run(
    request: Request,
    user: Principal = Depends(require_analyst),
) -> Response:
    """Agent run proxied to gateway /v1/agent/run (analyst+)."""
    return await _proxy_security(request, path="v1/agent/run", user=user)


@security_router.post("/api/v1/security/chat/completions")
async def proxy_chat_completions(
    request: Request,
    user: Principal = Depends(require_analyst),
) -> Response:
    """Chat completions proxied to gateway /v1/chat/completions (analyst+)."""
    return await _proxy_security(request, path="v1/chat/completions", user=user)


@security_router.get("/api/v1/security/agent/runs/{run_id}")
async def proxy_agent_run_status(
    run_id: str,
    request: Request,
    user: Principal = Depends(require_analyst),
) -> Response:
    """Paused agent run status proxied to gateway (analyst+, own runs only)."""
    return await _proxy_security(request, path=f"v1/agent/runs/{run_id}", user=user)


@security_router.post("/api/v1/security/agent/runs/{run_id}/resume")
async def proxy_agent_run_resume(
    run_id: str,
    request: Request,
    user: Principal = Depends(require_analyst),
) -> Response:
    """Resume a paused agent run with a server-issued approval id or a denial."""
    return await _proxy_security(request, path=f"v1/agent/runs/{run_id}/resume", user=user)
