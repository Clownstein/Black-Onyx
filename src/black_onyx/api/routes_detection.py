"""BFF proxy: Black Onyx session → detection-plane services."""

from __future__ import annotations

import json
import logging
import os
from typing import Any
from urllib.parse import quote, unquote

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import JSONResponse

from black_onyx.api.detection_adapters import adapt_body
from black_onyx.auth.dependencies import current_principal, require_analyst, require_viewer
from black_onyx.auth.service import Principal, Role
from black_onyx.detection_auth import mint_detection_token

logger = logging.getLogger(__name__)
detection_router = APIRouter(tags=["detection"])

UPSTREAMS = {
    "incident": os.environ.get("BLACK_ONYX_INCIDENT_API_URL", "http://incident-api:8083"),
    "assets": os.environ.get("BLACK_ONYX_ASSET_REGISTRY_URL", "http://asset-registry:8081"),
    "ti": os.environ.get("BLACK_ONYX_THREAT_INTEL_URL", "http://threat-intel-service:8098"),
    "hub": os.environ.get("BLACK_ONYX_INTEGRATION_HUB_URL", "http://integration-hub:8105"),
    "response": os.environ.get("BLACK_ONYX_RESPONSE_URL", "http://response-orchestrator:8111"),
    "notify": os.environ.get("BLACK_ONYX_NOTIFY_URL", "http://notification-service:8086"),
    "training": os.environ.get("BLACK_ONYX_TRAINING_URL", "http://training-orchestrator:8096"),
    "ingest": os.environ.get("BLACK_ONYX_INGEST_URL", "http://ingestion-gateway:8080"),
    "models": os.environ.get("BLACK_ONYX_MODEL_GATEWAY_URL", "http://model-gateway:8091"),
}

_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
MAX_PROXY_BODY_BYTES = 16 * 1024 * 1024
MAX_PROXY_RESPONSE_BYTES = 32 * 1024 * 1024
# Static malware analyze runs YARA/capa/FLOSS/ClamAV sequentially (up to ~120s each).
DEFAULT_PROXY_TIMEOUT_S = 60.0
MALWARE_PROXY_TIMEOUT_S = 300.0



def _tenant_id() -> str:
    tenant_id = os.environ.get("BLACK_ONYX_DETECTION_TENANT", "").strip()
    if not tenant_id:
        raise HTTPException(status_code=503, detail="Detection tenant is not configured")
    return tenant_id


def _token(user: Principal) -> str:
    return mint_detection_token(
        subject=user.email or user.user_id,
        role=user.role.value,
        tenant_id=_tenant_id(),
    )


def require_detection_access(request: Request, user: Principal = Depends(current_principal)) -> Principal:
    """Viewers may read; mutations require analyst/admin (Black Onyx roles)."""
    if request.method.upper() in _SAFE_METHODS:
        if user.role not in (Role.ADMIN, Role.ANALYST, Role.VIEWER):
            raise HTTPException(status_code=403, detail="Insufficient permission")
        return user
    if user.role not in (Role.ADMIN, Role.ANALYST):
        raise HTTPException(status_code=403, detail="Insufficient permission")
    return user


def _session_actor(user: Principal) -> str:
    return (user.email or user.user_id or "").strip() or "session"


def _inject_actor(
    path: str, method: str, body: bytes, user: Principal, *, upstream: str,
    content_type: str = "application/json",
) -> bytes:
    """Apply the declared operation adapter; session identity always wins."""
    if method.upper() in _SAFE_METHODS:
        return body
    return adapt_body(
        upstream, path, method, body,
        tenant_id=_tenant_id(), actor=_session_actor(user), content_type=content_type,
    )


def _response_service_key() -> str:
    return os.environ.get("RESPONSE_ORCHESTRATOR_API_KEY", "")


async def _check_response_asset(raw_body: bytes, user: Principal) -> None:
    """A response request may only target an asset that belongs to its incident."""
    try:
        requested = json.loads(raw_body.decode("utf-8") or "{}")
    except (UnicodeDecodeError, json.JSONDecodeError):
        return
    if not isinstance(requested, dict):
        return
    payload = requested.get("payload")
    asset_id = payload.get("asset_id") if isinstance(payload, dict) else None
    if asset_id is None:
        return
    incident_id = str(requested.get("incident_id") or "").strip()
    if not isinstance(asset_id, str) or not asset_id.strip() or not incident_id:
        raise HTTPException(status_code=422, detail="payload.asset_id and incident_id are required together")
    url = f"{UPSTREAMS['incident'].rstrip('/')}/api/v1/incidents/{quote(incident_id, safe='')}"
    headers = {
        "Authorization": f"Bearer {_token(user)}",
        "X-Tenant-Id": _tenant_id(),
        "X-Role": user.role.value,
        "Accept": "application/json",
    }
    try:
        async with httpx.AsyncClient(timeout=15.0, trust_env=False, follow_redirects=False) as client:
            response = await client.get(url, headers=headers)
    except httpx.HTTPError as exc:
        raise HTTPException(
            status_code=502, detail=f"Detection upstream unavailable: {exc.__class__.__name__}",
        ) from exc
    if response.status_code == 404:
        raise HTTPException(status_code=404, detail="Incident not found")
    if response.status_code != 200:
        raise HTTPException(status_code=502, detail=f"Incident lookup failed ({response.status_code})")
    try:
        incident = response.json()
    except ValueError as exc:
        raise HTTPException(status_code=502, detail="Incident lookup returned invalid JSON") from exc
    assets = incident.get("assets") if isinstance(incident, dict) else None
    if not isinstance(assets, list) or asset_id.strip() not in {str(a) for a in assets}:
        raise HTTPException(status_code=422, detail="payload.asset_id is not an asset of this incident")


async def _proxy(
    request: Request,
    *,
    upstream: str,
    path: str,
    user: Principal,
    service_key_env: str | None = None,
) -> Response:
    base = UPSTREAMS[upstream]
    decoded_path = unquote(path).replace("\\", "/")
    relative_path = decoded_path.lstrip("/")
    if (
        not relative_path
        or "//" in relative_path
        or any(
            part in {".", ".."} or any(ord(char) < 32 for char in part)
            for part in relative_path.split("/")
        )
    ):
        raise HTTPException(status_code=400, detail="Invalid detection proxy path")
    url = f"{base.rstrip('/')}/{relative_path}"
    if any(value != _tenant_id() for value in request.query_params.getlist("tenant_id")):
        raise HTTPException(status_code=403, detail="tenant_id does not match session tenant")
    if request.url.query:
        url = f"{url}?{request.url.query}"
    headers = {
        "Authorization": f"Bearer {_token(user)}",
        "X-Tenant-Id": _tenant_id(),
        "X-Role": user.role.value,
        "Accept": request.headers.get("accept", "application/json"),
        "Content-Type": request.headers.get("content-type", "application/json"),
    }
    if (
        upstream == "training"
        and request.method.upper() == "POST"
        and relative_path.startswith("api/v1/models/")
        and relative_path.endswith("/training-jobs")
    ):
        idempotency_key = request.headers.get("idempotency-key", "")
        if idempotency_key:
            if len(idempotency_key) > 128 or not all(
                char.isascii() and (char.isalnum() or char in "-_.:")
                for char in idempotency_key
            ):
                raise HTTPException(status_code=400, detail="Invalid Idempotency-Key")
            headers["Idempotency-Key"] = idempotency_key
    if service_key_env:
        key = (
            _response_service_key()
            if service_key_env == "RESPONSE_ORCHESTRATOR_API_KEY"
            else os.environ.get(service_key_env, "")
        )
        if key:
            headers["X-Service-Key"] = key.split(",")[0].strip()
            headers["X-API-Key"] = key.split(",")[0].strip()
    if (
        service_key_env == "RESPONSE_ORCHESTRATOR_API_KEY"
        and request.method.upper() == "POST"
        and relative_path.endswith("/approve")
    ):
        # The browser cannot supply this credential. Only an administrator
        # may request a live transition through the BFF.
        try:
            requested = json.loads((await request.body()).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            requested = {}
        if isinstance(requested, dict) and requested.get("dry_run") is False:
            if user.role != Role.ADMIN:
                raise HTTPException(status_code=403, detail="Live response approval requires admin")
            approver_key = os.environ.get("RESPONSE_ORCHESTRATOR_APPROVER_API_KEY", "")
            if not approver_key:
                raise HTTPException(status_code=503, detail="Live response approval is not configured")
            headers["X-Approver-Key"] = approver_key
    if (
        service_key_env == "RESPONSE_ORCHESTRATOR_API_KEY"
        and (
            (request.method.upper() == "GET" and relative_path == "api/v1/response/reconciliation")
            or (request.method.upper() == "POST" and relative_path == "api/v1/response/reconciliation/scan")
        )
    ):
        if user.role != Role.ADMIN:
            raise HTTPException(status_code=403, detail="Response reconciliation requires admin")
        approver_key = os.environ.get("RESPONSE_ORCHESTRATOR_APPROVER_API_KEY", "")
        if not approver_key:
            raise HTTPException(status_code=503, detail="Response reconciliation is not configured")
        headers["X-Approver-Key"] = approver_key
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > MAX_PROXY_BODY_BYTES:
                raise HTTPException(status_code=413, detail="Detection proxy body is too large")
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Invalid Content-Length") from exc
    raw_body = await request.body()
    if len(raw_body) > MAX_PROXY_BODY_BYTES:
        raise HTTPException(status_code=413, detail="Detection proxy body is too large")
    if (
        upstream in {"response", "hub"}
        and request.method.upper() == "POST"
        and relative_path == "api/v1/response/request"
    ):
        await _check_response_asset(raw_body, user)
    body = _inject_actor(
        relative_path, request.method, raw_body, user,
        upstream=upstream, content_type=headers["Content-Type"],
    )
    timeout_s = DEFAULT_PROXY_TIMEOUT_S
    if upstream == "ingest" and relative_path.startswith("api/v1/malware/analyze"):
        timeout_s = MALWARE_PROXY_TIMEOUT_S
    try:
        async with httpx.AsyncClient(timeout=timeout_s, trust_env=False, follow_redirects=False) as client:
            async with client.stream(
                request.method,
                url,
                content=body or None,
                headers=headers,
            ) as upstream:
                upstream_length = upstream.headers.get("content-length")
                if upstream_length:
                    try:
                        if int(upstream_length) > MAX_PROXY_RESPONSE_BYTES:
                            return JSONResponse(
                                status_code=502,
                                content={"detail": "Detection upstream response is too large"},
                            )
                    except ValueError:
                        return JSONResponse(
                            status_code=502,
                            content={"detail": "Detection upstream returned an invalid Content-Length"},
                        )
                chunks: list[bytes] = []
                response_bytes = 0
                async for chunk in upstream.aiter_bytes():
                    response_bytes += len(chunk)
                    if response_bytes > MAX_PROXY_RESPONSE_BYTES:
                        return JSONResponse(
                            status_code=502,
                            content={"detail": "Detection upstream response is too large"},
                        )
                    chunks.append(chunk)
                response_body = b"".join(chunks)
                response_status = upstream.status_code
                response_headers = dict(upstream.headers)
    except httpx.HTTPError as exc:
        return JSONResponse(
            status_code=502,
            content={"detail": f"Detection upstream unavailable: {exc.__class__.__name__}"},
        )
    excluded = {"content-encoding", "transfer-encoding", "connection", "content-length"}
    out_headers = {k: v for k, v in response_headers.items() if k.lower() not in excluded}
    return Response(content=response_body, status_code=response_status, headers=out_headers)


@detection_router.get("/api/v1/detection/health")
async def detection_bff_health(user: Principal = Depends(require_viewer)) -> dict[str, Any]:
    return {
        "status": "ok",
        "tenant": _tenant_id(),
        "upstreams": list(UPSTREAMS.keys()),
        "user": user.email,
    }


@detection_router.api_route("/api/v1/detection/incident/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def proxy_incident(path: str, request: Request, user: Principal = Depends(require_detection_access)) -> Response:
    return await _proxy(request, upstream="incident", path=f"/{path}", user=user)


@detection_router.api_route("/api/v1/detection/assets/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def proxy_assets(path: str, request: Request, user: Principal = Depends(require_detection_access)) -> Response:
    return await _proxy(request, upstream="assets", path=f"/{path}", user=user)


@detection_router.api_route("/api/v1/detection/ti/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def proxy_ti(path: str, request: Request, user: Principal = Depends(require_analyst)) -> Response:
    return await _proxy(
        request,
        upstream="ti",
        path=f"/{path}",
        user=user,
        service_key_env="THREAT_INTEL_SERVICE_KEY",
    )


@detection_router.api_route("/api/v1/detection/hub/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def proxy_hub(path: str, request: Request, user: Principal = Depends(require_analyst)) -> Response:
    return await _proxy(
        request,
        upstream="hub",
        path=f"/{path}",
        user=user,
        service_key_env="INTEGRATION_HUB_API_KEY",
    )


@detection_router.api_route("/api/v1/detection/response/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def proxy_response(path: str, request: Request, user: Principal = Depends(require_analyst)) -> Response:
    return await _proxy(
        request,
        upstream="response",
        path=f"/{path}",
        user=user,
        service_key_env="RESPONSE_ORCHESTRATOR_API_KEY",
    )


@detection_router.api_route("/api/v1/detection/notify/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def proxy_notify(path: str, request: Request, user: Principal = Depends(require_analyst)) -> Response:
    return await _proxy(
        request,
        upstream="notify",
        path=f"/{path}",
        user=user,
        service_key_env="NOTIFICATION_API_KEY",
    )


@detection_router.api_route("/api/v1/detection/training/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def proxy_training(path: str, request: Request, user: Principal = Depends(require_analyst)) -> Response:
    return await _proxy(
        request,
        upstream="training",
        path=f"/{path}",
        user=user,
        service_key_env="TRAINING_API_KEY",
    )


@detection_router.api_route("/api/v1/detection/ingest/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def proxy_ingest(path: str, request: Request, user: Principal = Depends(require_analyst)) -> Response:
    return await _proxy(
        request,
        upstream="ingest",
        path=f"/{path}",
        user=user,
        service_key_env="API_KEYS",
    )


@detection_router.api_route("/api/v1/detection/models/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def proxy_models(path: str, request: Request, user: Principal = Depends(require_analyst)) -> Response:
    return await _proxy(
        request,
        upstream="models",
        path=f"/{path}",
        user=user,
        service_key_env="MODEL_GATEWAY_API_KEY",
    )


@detection_router.post("/api/v1/auth/detection-token")
async def issue_detection_token(_: Principal = Depends(require_analyst)) -> JSONResponse:
    """Browser minting is disabled detection JWTs are minted only inside the BFF proxy."""
    return JSONResponse(
        status_code=410,
        content={
            "detail": "Detection tokens are minted server-side by /api/v1/detection/* proxies. Do not request browser-held detection JWTs.",
        },
    )
