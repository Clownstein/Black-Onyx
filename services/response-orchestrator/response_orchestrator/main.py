"""Response orchestrator — approval-gated SOAR playbooks."""

from __future__ import annotations

import secrets
from contextlib import asynccontextmanager
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from response_orchestrator import response as response_svc
from response_orchestrator.config import settings
from response_orchestrator.db import get_db, init_db
from response_orchestrator.playbooks import list_playbooks

try:
    from black_onyx_otel import install_prometheus_endpoint, setup_tracing

    setup_tracing("response-orchestrator")
except Exception:
    install_prometheus_endpoint = None  # type: ignore[assignment]


def _check_api_key(x_api_key: str | None) -> None:
    expected = settings.api_key
    if not expected:
        return
    if not x_api_key or not secrets.compare_digest(x_api_key, expected):
        raise HTTPException(status_code=401, detail="invalid or missing X-API-Key")


def _allow_live_override(x_approver_key: str | None) -> bool:
    elevated = settings.approver_api_key
    if not elevated or not x_approver_key:
        return False
    return secrets.compare_digest(x_approver_key, elevated)


def _require_tenant(x_tenant_id: str | None) -> str:
    if not x_tenant_id or not x_tenant_id.strip():
        raise HTTPException(status_code=400, detail="X-Tenant-Id required")
    return x_tenant_id.strip()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    yield


app = FastAPI(title="Response Orchestrator", version="0.1.0", lifespan=lifespan)
if install_prometheus_endpoint is not None:
    install_prometheus_endpoint(app)


class RequestBody(BaseModel):
    tenant_id: str = Field(min_length=1)
    incident_id: str = Field(min_length=1)
    playbook_id: str = Field(min_length=1)
    action: str = "execute"
    dry_run: bool | None = None
    payload: dict[str, Any] = Field(default_factory=dict)
    actor: str = Field(min_length=1)


class ApproveBody(BaseModel):
    actor: str = Field(min_length=1)
    dry_run: bool | None = None


def _row_dict(row: Any) -> dict[str, Any]:
    return {
        "request_id": row.request_id,
        "tenant_id": row.tenant_id,
        "incident_id": row.incident_id,
        "playbook_id": row.playbook_id,
        "action": row.action,
        "status": row.status,
        "dry_run": row.dry_run,
        "payload": row.payload,
        "result": row.result,
        "approved_by": row.approved_by,
        "approval_required": True,
    }


@app.get("/health/live")
def live() -> dict[str, str]:
    return {"status": "alive"}


@app.get("/health/ready")
def ready() -> dict[str, object]:
    return {
        "status": "ready",
        "dry_run_default": settings.dry_run_default,
        "api_key_required": bool(settings.api_key),
        "port": settings.port,
    }


@app.get("/api/v1/playbooks")
def get_playbooks(x_api_key: str | None = Header(default=None, alias="X-API-Key")) -> dict[str, Any]:
    _check_api_key(x_api_key)
    return {"items": list_playbooks()}


@app.post("/api/v1/response/request")
def create_response_request(
    body: RequestBody,
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-Id"),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    _check_api_key(x_api_key)
    tenant_id = x_tenant_id or body.tenant_id
    row = response_svc.create_request(
        db,
        tenant_id=tenant_id,
        incident_id=body.incident_id,
        playbook_id=body.playbook_id,
        action=body.action,
        dry_run=body.dry_run,
        payload=body.payload,
        actor=body.actor,
    )
    return _row_dict(row)


@app.post("/api/v1/response/{request_id}/approve")
def approve(
    request_id: str,
    body: ApproveBody,
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    x_approver_key: str | None = Header(default=None, alias="X-Approver-Key"),
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-Id"),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    _check_api_key(x_api_key)
    tenant_id = _require_tenant(x_tenant_id)
    try:
        row = response_svc.approve_request(
            db,
            request_id=request_id,
            actor=body.actor,
            dry_run_override=body.dry_run,
            tenant_id=tenant_id,
            allow_live_override=_allow_live_override(x_approver_key),
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="request not found") from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return _row_dict(row)


@app.post("/api/v1/response/{request_id}/reject")
def reject(
    request_id: str,
    body: ApproveBody,
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-Id"),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    _check_api_key(x_api_key)
    tenant_id = _require_tenant(x_tenant_id)
    try:
        row = response_svc.reject_request(
            db,
            request_id=request_id,
            actor=body.actor,
            tenant_id=tenant_id,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="request not found") from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return _row_dict(row)


@app.get("/api/v1/response/pending")
def list_pending(
    limit: int = Query(default=100, ge=1, le=500),
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-Id"),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    _check_api_key(x_api_key)
    tid = _require_tenant(x_tenant_id)
    rows = response_svc.list_pending(db, tenant_id=tid, limit=limit)
    return {"items": [_row_dict(r) for r in rows]}


@app.get("/api/v1/response/audit")
def audit(
    tenant_id: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-Id"),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    _check_api_key(x_api_key)
    tid = _require_tenant(tenant_id or x_tenant_id)
    rows = response_svc.list_audit(db, tenant_id=tid, limit=limit)
    return {
        "items": [
            {
                "id": r.id,
                "tenant_id": r.tenant_id,
                "request_id": r.request_id,
                "action": r.action,
                "actor": r.actor,
                "detail": r.detail,
            }
            for r in rows
        ]
    }


@app.get("/api/v1/response/{request_id}")
def get_request(
    request_id: str,
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-Id"),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    _check_api_key(x_api_key)
    tenant_id = _require_tenant(x_tenant_id)
    row = response_svc.get_request(db, request_id, tenant_id=tenant_id)
    if row is None:
        raise HTTPException(status_code=404, detail="request not found")
    return _row_dict(row)


def run() -> None:
    import uvicorn

    uvicorn.run("response_orchestrator.main:app", host=settings.host, port=settings.port, reload=False)


if __name__ == "__main__":
    run()
