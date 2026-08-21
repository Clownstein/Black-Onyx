"""BFF proxy: Black Onyx session → detection-plane services (absorbed AutoAnalyzer)."""

from __future__ import annotations

import json
import os
from typing import Any

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import JSONResponse

from black_onyx.auth.dependencies import current_principal, require_analyst, require_viewer
from black_onyx.auth.service import Principal, Role
from black_onyx.detection_auth import mint_detection_token

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

TENANT_ID = os.environ.get("BLACK_ONYX_DETECTION_TENANT", "default")
_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
_ACTOR_PATH_SUFFIXES = (
    "/disposition",
    "/acknowledge",
    "/approve",
    "/reject",
    "/response/request",
    "/training-jobs",
    "/comments",
    "/feedback",
)


def _token(user: Principal) -> str:
    return mint_detection_token(subject=user.email or user.user_id, role=user.role.value, tenant_id=TENANT_ID)


def require_detection_access(request: Request, user: Principal = Depends(current_principal)) -> Principal:
    """Viewers may read; mutations require analyst/admin (Black Onyx roles)."""
    if request.method.upper() in _SAFE_METHODS:
        if user.role not in (Role.ADMIN, Role.ANALYST, Role.VIEWER):
            raise HTTPException(status_code=403, detail="Insufficient permission")
        return user
    if user.role not in (Role.ADMIN, Role.ANALYST):
        raise HTTPException(status_code=403, detail="Insufficient permission")
    return user


def _inject_actor(path: str, method: str, body: bytes, user: Principal) -> bytes:
    """Stamp session identity into mutation JSON for upstream audit trails.

    Session identity always wins for actor/author/created_by on mutation bodies —
    clients cannot spoof audit fields.
    """
    if method.upper() in _SAFE_METHODS or not body:
        return body
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return body
    if not isinstance(payload, dict):
        return body
    actor = (user.email or user.user_id or "").strip() or "session"
    payload["tenant_id"] = TENANT_ID
    lowered = "/" + path.lstrip("/").lower()
    needs_actor = any(
        lowered.endswith(suffix) or f"{suffix}/" in lowered or suffix in lowered
        for suffix in _ACTOR_PATH_SUFFIXES
    )
    if needs_actor:
        payload["actor"] = actor
    if lowered.endswith("/comments"):
        payload["author"] = actor
    if lowered.endswith("/training-jobs"):
        payload["created_by"] = actor
    for key in ("actor", "author", "created_by"):
        if key in payload:
            payload[key] = actor
    if "owner" in payload and str(payload.get("owner") or "").strip() in ("", "session"):
        payload["owner"] = actor
    return json.dumps(payload, separators=(",", ":")).encode("utf-8")


async def _proxy(
    request: Request,
    *,
    base: str,
    path: str,
    user: Principal,
    service_key_env: str | None = None,
) -> Response:
    url = f"{base.rstrip('/')}/{path.lstrip('/')}"
    if request.url.query:
        url = f"{url}?{request.url.query}"
    headers = {
        "Authorization": f"Bearer {_token(user)}",
        "X-Tenant-Id": TENANT_ID,
        "X-Role": user.role.value,
        "Accept": request.headers.get("accept", "application/json"),
        "Content-Type": request.headers.get("content-type", "application/json"),
    }
    if service_key_env:
        key = os.environ.get(service_key_env, "")
        if key:
            headers["X-Service-Key"] = key.split(",")[0].strip()
            headers["X-API-Key"] = key.split(",")[0].strip()
    body = _inject_actor(path, request.method, await request.body(), user)
    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            upstream = await client.request(request.method, url, content=body or None, headers=headers)
    except httpx.HTTPError as exc:
        return JSONResponse(
            status_code=502,
            content={"detail": f"Detection upstream unavailable: {exc.__class__.__name__}"},
        )
    excluded = {"content-encoding", "transfer-encoding", "connection"}
    out_headers = {k: v for k, v in upstream.headers.items() if k.lower() not in excluded}
    return Response(content=upstream.content, status_code=upstream.status_code, headers=out_headers)


@detection_router.get("/api/v1/detection/health")
async def detection_bff_health(user: Principal = Depends(require_viewer)) -> dict[str, Any]:
    return {"status": "ok", "tenant": TENANT_ID, "upstreams": list(UPSTREAMS.keys()), "user": user.email}


@detection_router.api_route("/api/v1/detection/incident/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def proxy_incident(path: str, request: Request, user: Principal = Depends(require_detection_access)) -> Response:
    return await _proxy(request, base=UPSTREAMS["incident"], path=f"/{path}", user=user)


@detection_router.api_route("/api/v1/detection/assets/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def proxy_assets(path: str, request: Request, user: Principal = Depends(require_detection_access)) -> Response:
    return await _proxy(request, base=UPSTREAMS["assets"], path=f"/{path}", user=user)


@detection_router.api_route("/api/v1/detection/ti/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def proxy_ti(path: str, request: Request, user: Principal = Depends(require_analyst)) -> Response:
    return await _proxy(
        request,
        base=UPSTREAMS["ti"],
        path=f"/{path}",
        user=user,
        service_key_env="THREAT_INTEL_SERVICE_KEY",
    )


@detection_router.api_route("/api/v1/detection/hub/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def proxy_hub(path: str, request: Request, user: Principal = Depends(require_analyst)) -> Response:
    return await _proxy(
        request,
        base=UPSTREAMS["hub"],
        path=f"/{path}",
        user=user,
        service_key_env="INTEGRATION_HUB_API_KEY",
    )


@detection_router.api_route("/api/v1/detection/response/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def proxy_response(path: str, request: Request, user: Principal = Depends(require_analyst)) -> Response:
    return await _proxy(
        request,
        base=UPSTREAMS["response"],
        path=f"/{path}",
        user=user,
        service_key_env="RESPONSE_API_KEY",
    )


@detection_router.api_route("/api/v1/detection/notify/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def proxy_notify(path: str, request: Request, user: Principal = Depends(require_analyst)) -> Response:
    return await _proxy(
        request,
        base=UPSTREAMS["notify"],
        path=f"/{path}",
        user=user,
        service_key_env="NOTIFICATION_API_KEY",
    )


@detection_router.api_route("/api/v1/detection/training/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def proxy_training(path: str, request: Request, user: Principal = Depends(require_analyst)) -> Response:
    return await _proxy(request, base=UPSTREAMS["training"], path=f"/{path}", user=user)


@detection_router.api_route("/api/v1/detection/ingest/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def proxy_ingest(path: str, request: Request, user: Principal = Depends(require_analyst)) -> Response:
    return await _proxy(
        request,
        base=UPSTREAMS["ingest"],
        path=f"/{path}",
        user=user,
        service_key_env="API_KEYS",
    )


@detection_router.api_route("/api/v1/detection/models/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def proxy_models(path: str, request: Request, user: Principal = Depends(require_analyst)) -> Response:
    return await _proxy(request, base=UPSTREAMS["models"], path=f"/{path}", user=user)


@detection_router.post("/api/v1/auth/detection-token")
async def issue_detection_token(_: Principal = Depends(require_analyst)) -> JSONResponse:
    """Browser minting is disabled — detection JWTs are minted only inside the BFF proxy."""
    return JSONResponse(
        status_code=410,
        content={
            "detail": "Detection tokens are minted server-side by /api/v1/detection/* proxies. Do not request browser-held detection JWTs.",
        },
    )
