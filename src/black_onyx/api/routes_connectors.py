"""Detection connector API — CRUD, poll-now, and test-connection for
pull-based SIEM/EDR sources.

A standalone router module rather than more additions to the already
2600+-line `api/routes.py`, following the same separate-module precedent
`taxii/server.py` set for TAXII: this feature is large enough (CRUD + poll +
test + a recent-detections read) to earn its own file.
"""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request

from black_onyx.api.schemas import (
    ConnectorCreateRequest,
    ConnectorPushRequest,
    ConnectorResponse,
    ConnectorUpdateRequest,
)
from black_onyx.auth.dependencies import require_admin, require_analyst
from black_onyx.auth.service import Principal, Role
from black_onyx.rate_limit import SlidingWindowLimiter

logger = logging.getLogger(__name__)

connectors_router = APIRouter(tags=["connectors"])
_PUSH_LIMITER = SlidingWindowLimiter()
_PUSH_MAX = 60
_PUSH_WINDOW = timedelta(minutes=1)


def _get_service():
    from black_onyx.api.service import get_service
    return get_service()


def _connector_row_to_response(row: dict[str, Any]) -> ConnectorResponse:
    payload = {
        k: row.get(k)
        for k in ConnectorResponse.model_fields
    }
    return ConnectorResponse(**payload)


def _extract_bearer_or_header(request: Request) -> str:
    token = request.headers.get("x-connector-token", "") or ""
    if token:
        return token.strip()
    auth = request.headers.get("authorization", "") or ""
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return ""


def _get_or_404(connector_id: str) -> dict[str, Any]:
    row = _get_service().connector_manager.get_connector(connector_id)
    if not row:
        raise HTTPException(status_code=404, detail="Connector not found")
    return row


# Detection connectors are an org-wide, admin-managed integration surface —
# unlike user_sites (personal, owner-scoped), a pulled SIEM/EDR feed's
# collection is shared data every analyst can already see through Search,
# Graph, and Cases, so its *configuration* (including which env vars hold
# its credentials) is admin-only, matching how /feeds and /admin/settings
# are gated.


@connectors_router.get("/api/v1/connectors", response_model=list[ConnectorResponse])
async def list_connectors(_: Principal = Depends(require_admin)) -> list[ConnectorResponse]:
    """List configured detection connectors."""
    return [_connector_row_to_response(row) for row in _get_service().connector_manager.list_connectors()]


@connectors_router.post("/api/v1/connectors", response_model=ConnectorResponse)
async def create_connector(
    req: ConnectorCreateRequest, principal: Principal = Depends(require_admin),
) -> ConnectorResponse:
    """Register a new detection connector."""
    service = _get_service()
    try:
        row = service.connector_manager.add_connector(
            name=req.name.strip(),
            connector_type=req.connector_type,
            base_url=req.base_url,
            config=req.config,
            credential_env=req.credential_env,
            collection=req.collection,
            poll_interval_minutes=req.poll_interval_minutes,
            tenant_id=req.tenant_id,
            enabled=req.enabled,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    from black_onyx.auth.context import get_auth_service
    get_auth_service().audit(
        principal, "connector.create", "connector", row["id"],
        detail={"connector_type": req.connector_type, "base_url": req.base_url},
    )
    return _connector_row_to_response(row)


@connectors_router.patch("/api/v1/connectors/{connector_id}", response_model=ConnectorResponse)
async def update_connector(
    connector_id: str, req: ConnectorUpdateRequest, principal: Principal = Depends(require_admin),
) -> ConnectorResponse:
    """Enable/disable a connector or change its poll interval."""
    _get_or_404(connector_id)
    row = _get_service().connector_manager.update_connector(
        connector_id, enabled=req.enabled, poll_interval_minutes=req.poll_interval_minutes,
    )
    from black_onyx.auth.context import get_auth_service
    get_auth_service().audit(principal, "connector.update", "connector", connector_id)
    return _connector_row_to_response(row)  # type: ignore[arg-type]


@connectors_router.delete("/api/v1/connectors/{connector_id}")
async def delete_connector(
    connector_id: str, principal: Principal = Depends(require_admin),
) -> dict[str, str]:
    """Remove a detection connector. Does not delete its ingested Qdrant
    collection — pulled detections remain searchable/case-linkable like any
    other ingested data even after the connector configuration is gone."""
    _get_or_404(connector_id)
    _get_service().connector_manager.delete_connector(connector_id)
    from black_onyx.auth.context import get_auth_service
    get_auth_service().audit(principal, "connector.delete", "connector", connector_id)
    return {"status": "ok", "message": f"Deleted connector: {connector_id}"}


@connectors_router.post("/api/v1/connectors/{connector_id}/poll")
async def poll_connector_now(
    connector_id: str, principal: Principal = Depends(require_admin),
) -> dict[str, Any]:
    """Poll one connector immediately, outside its scheduled interval."""
    _get_or_404(connector_id)
    result = await _get_service().connector_manager.poll_connector(connector_id)
    from black_onyx.auth.context import get_auth_service
    get_auth_service().audit(principal, "connector.poll", "connector", connector_id, detail=result)
    return result


@connectors_router.post("/api/v1/connectors/{connector_id}/push-token")
async def rotate_connector_push_token(
    connector_id: str,
    principal: Principal = Depends(require_admin),
) -> dict[str, Any]:
    """Create/rotate a machine push token (plaintext shown once)."""
    _get_or_404(connector_id)
    rotated = _get_service().connector_manager.rotate_push_token(connector_id)
    if not rotated:
        raise HTTPException(status_code=404, detail="Connector not found")
    from black_onyx.auth.context import get_auth_service
    get_auth_service().audit(principal, "connector.push_token.rotate", "connector", connector_id)
    return {
        "connector_id": connector_id,
        "token": rotated.get("push_token") or rotated.get("token"),
        "token_prefix": rotated.get("push_token_prefix"),
        "auth_header": "X-Connector-Token or Authorization: Bearer <token>",
    }


@connectors_router.post("/api/v1/connectors/{connector_id}/push")
async def push_connector_detections(
    connector_id: str,
    req: ConnectorPushRequest,
    request: Request,
) -> dict[str, Any]:
    """Push-ingest detections via admin session or connector push token."""
    service = _get_service()
    principal: Principal | None = getattr(request.state, "principal", None)
    token = _extract_bearer_or_header(request)
    if token:
        row = service.connector_manager.authenticate_push_token(connector_id, token)
        if not row:
            raise HTTPException(status_code=401, detail="Invalid connector push token")
        actor = f"push-token:{row.get('push_token_prefix') or connector_id}"
    elif principal and principal.role == Role.ADMIN:
        _get_or_404(connector_id)
        actor = principal.user_id
    else:
        raise HTTPException(
            status_code=401,
            detail="Admin session or X-Connector-Token required",
        )

    client_ip = request.client.host if request.client else "unknown"
    if not _PUSH_LIMITER.check(f"push:{connector_id}:{client_ip}", _PUSH_MAX, _PUSH_WINDOW):
        raise HTTPException(status_code=429, detail="Connector push rate limit exceeded")

    result = await service.connector_manager.push_detections(
        connector_id, list(req.detections or []),
    )
    if result.get("error") == "Connector not found":
        raise HTTPException(status_code=404, detail="Connector not found")
    from black_onyx.auth.context import get_auth_service
    if principal:
        get_auth_service().audit(
            principal, "connector.push", "connector", connector_id,
            detail={"processed": result.get("processed"), "raw_count": result.get("raw_count"), "actor": actor},
        )
    else:
        logger.info(
            "connector.push token ingest connector=%s processed=%s actor=%s",
            connector_id, result.get("processed"), actor,
        )
    return result


@connectors_router.post("/api/v1/connectors/{connector_id}/test")
async def test_connector(
    connector_id: str, _: Principal = Depends(require_admin),
) -> dict[str, Any]:
    """Verify a connector's credentials/reachability without pulling detections."""
    _get_or_404(connector_id)
    return await _get_service().connector_manager.test_connector(connector_id)


@connectors_router.get("/api/v1/connectors/detections/recent")
async def recent_detections(
    limit: int = 20, _: Principal = Depends(require_analyst),
) -> list[dict[str, Any]]:
    """Recent pulled detections across every connector, for the Dashboard
    and Detections page — read-only convenience for analyst+ operators.
    Connector configuration CRUD remains admin-only."""
    service = _get_service()
    bounded_limit = max(1, min(limit, 100))
    return service.connector_manager.list_recent_detections(service.qdrant_store, limit=bounded_limit)
