"""Tenant-scoped deployment, saved-hunt, notification, and audit APIs."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from incident_api.db import get_db
from incident_api.deployment_store import persist_deployment
from incident_api.models import (
    AuditRow,
    DeploymentEventRow,
    NotificationSettingRow,
    OperationalAuditRow,
    SavedHuntRow,
)
from incident_api.schemas import (
    DeploymentEventCreate,
    DeploymentEventRead,
    NotificationSettingRead,
    NotificationSettingWrite,
    SavedHuntCreate,
    SavedHuntRead,
)
from incident_api.tenant import Principal, require_role, require_tenant

router = APIRouter(prefix="/api/v1", tags=["operations"])

_SENSITIVE_CONFIG_KEYS = {
    "api_key",
    "authorization",
    "password",
    "secret",
    "token",
    "webhook_secret",
}


def _public_config(config: dict[str, Any]) -> dict[str, Any]:
    return {
        key: ("***" if key.lower() in _SENSITIVE_CONFIG_KEYS else value)
        for key, value in config.items()
    }


def _deployment_read(row: DeploymentEventRow) -> DeploymentEventRead:
    return DeploymentEventRead.model_validate(row)


@router.get("/deployments", response_model=list[DeploymentEventRead])
def list_deployments(
    tenant_id: str = Depends(require_tenant),
    db: Session = Depends(get_db),
    service_id: str | None = Query(default=None),
    environment: str | None = Query(default=None),
    commit_sha: str | None = Query(default=None),
) -> list[DeploymentEventRead]:
    stmt = select(DeploymentEventRow).where(DeploymentEventRow.tenant_id == tenant_id)
    if service_id:
        stmt = stmt.where(DeploymentEventRow.service_id == service_id)
    if environment:
        stmt = stmt.where(DeploymentEventRow.environment == environment)
    if commit_sha:
        stmt = stmt.where(DeploymentEventRow.commit_sha == commit_sha)
    stmt = stmt.order_by(DeploymentEventRow.deployed_at.desc())
    return [_deployment_read(row) for row in db.scalars(stmt).all()]


@router.post("/deployments", response_model=DeploymentEventRead, status_code=201)
def upsert_deployment(
    body: DeploymentEventCreate,
    tenant_id: str = Depends(require_tenant),
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_role("analyst")),
) -> DeploymentEventRead:
    row = persist_deployment(
        db,
        tenant_id=tenant_id,
        body=body,
        actor=principal.subject,
    )
    return _deployment_read(row)


@router.get("/saved-hunts", response_model=list[SavedHuntRead])
def list_saved_hunts(
    tenant_id: str = Depends(require_tenant),
    db: Session = Depends(get_db),
) -> list[SavedHuntRead]:
    rows = db.scalars(
        select(SavedHuntRow)
        .where(SavedHuntRow.tenant_id == tenant_id)
        .order_by(SavedHuntRow.updated_at.desc())
    ).all()
    return [SavedHuntRead.model_validate(row) for row in rows]


@router.post("/saved-hunts", response_model=SavedHuntRead, status_code=201)
def save_hunt(
    body: SavedHuntCreate,
    tenant_id: str = Depends(require_tenant),
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_role("analyst")),
) -> SavedHuntRead:
    hunt_id = body.hunt_id or f"hunt-{uuid4().hex[:16]}"
    row = db.scalar(
        select(SavedHuntRow).where(
            SavedHuntRow.tenant_id == tenant_id,
            SavedHuntRow.hunt_id == hunt_id,
        )
    )
    if row is None:
        row = SavedHuntRow(
            hunt_id=hunt_id,
            tenant_id=tenant_id,
            name=body.name,
            query=body.query,
            query_type=body.query_type,
            filters=body.filters,
            created_by=principal.subject,
        )
        db.add(row)
    else:
        row.name = body.name
        row.query = body.query
        row.query_type = body.query_type
        row.filters = body.filters
    db.add(
        OperationalAuditRow(
            tenant_id=tenant_id,
            resource_type="saved_hunt",
            resource_id=hunt_id,
            action="saved",
            actor=principal.subject,
            detail={"name": body.name, "query_type": body.query_type},
        )
    )
    db.commit()
    db.refresh(row)
    return SavedHuntRead.model_validate(row)


@router.delete("/saved-hunts/{hunt_id}", status_code=204)
def delete_saved_hunt(
    hunt_id: str,
    tenant_id: str = Depends(require_tenant),
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_role("analyst")),
) -> Response:
    row = db.scalar(
        select(SavedHuntRow).where(
            SavedHuntRow.tenant_id == tenant_id,
            SavedHuntRow.hunt_id == hunt_id,
        )
    )
    if row is None:
        raise HTTPException(status_code=404, detail="saved hunt not found")
    db.delete(row)
    db.add(
        OperationalAuditRow(
            tenant_id=tenant_id,
            resource_type="saved_hunt",
            resource_id=hunt_id,
            action="deleted",
            actor=principal.subject,
            detail={},
        )
    )
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/settings/notifications", response_model=list[NotificationSettingRead])
def list_notification_settings(
    tenant_id: str = Depends(require_tenant),
    db: Session = Depends(get_db),
) -> list[NotificationSettingRead]:
    rows = db.scalars(
        select(NotificationSettingRow)
        .where(NotificationSettingRow.tenant_id == tenant_id)
        .order_by(NotificationSettingRow.channel.asc())
    ).all()
    return [
        NotificationSettingRead(
            setting_id=row.setting_id,
            tenant_id=row.tenant_id,
            channel=row.channel,
            enabled=row.enabled,
            config=_public_config(dict(row.config or {})),
            updated_by=row.updated_by,
            created_at=row.created_at,
            updated_at=row.updated_at,
        )
        for row in rows
    ]


@router.put("/settings/notifications/{setting_id}", response_model=NotificationSettingRead)
def write_notification_setting(
    setting_id: str,
    body: NotificationSettingWrite,
    tenant_id: str = Depends(require_tenant),
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_role("admin")),
) -> NotificationSettingRead:
    if body.setting_id and body.setting_id != setting_id:
        raise HTTPException(status_code=400, detail="setting_id does not match path")
    row = db.scalar(
        select(NotificationSettingRow).where(
            NotificationSettingRow.tenant_id == tenant_id,
            NotificationSettingRow.setting_id == setting_id,
        )
    )
    if row is None:
        row = NotificationSettingRow(
            setting_id=setting_id,
            tenant_id=tenant_id,
            channel=body.channel,
            enabled=body.enabled,
            config=body.config,
            updated_by=principal.subject,
        )
        db.add(row)
    else:
        row.channel = body.channel
        row.enabled = body.enabled
        row.config = body.config
        row.updated_by = principal.subject
    db.add(
        OperationalAuditRow(
            tenant_id=tenant_id,
            resource_type="notification_setting",
            resource_id=setting_id,
            action="updated",
            actor=principal.subject,
            detail={"channel": body.channel, "enabled": body.enabled},
        )
    )
    db.commit()
    db.refresh(row)
    return NotificationSettingRead(
        setting_id=row.setting_id,
        tenant_id=row.tenant_id,
        channel=row.channel,
        enabled=row.enabled,
        config=_public_config(dict(row.config or {})),
        updated_by=row.updated_by,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


@router.get("/audit")
def list_audit(
    tenant_id: str = Depends(require_tenant),
    db: Session = Depends(get_db),
    incident_id: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
) -> dict[str, Any]:
    incident_stmt = select(AuditRow).where(AuditRow.tenant_id == tenant_id)
    if incident_id:
        incident_stmt = incident_stmt.where(AuditRow.incident_id == incident_id)
    incident_rows = db.scalars(
        incident_stmt.order_by(AuditRow.created_at.desc()).limit(limit)
    ).all()
    operational_rows = []
    if not incident_id:
        operational_rows = db.scalars(
            select(OperationalAuditRow)
            .where(OperationalAuditRow.tenant_id == tenant_id)
            .order_by(OperationalAuditRow.created_at.desc())
            .limit(limit)
        ).all()
    items = [
        {
            "resource_type": "incident",
            "resource_id": row.incident_id,
            "action": row.action,
            "detail": row.detail,
            "created_at": row.created_at,
        }
        for row in incident_rows
    ]
    items.extend(
        {
            "resource_type": row.resource_type,
            "resource_id": row.resource_id,
            "action": row.action,
            "actor": row.actor,
            "detail": row.detail,
            "created_at": row.created_at,
        }
        for row in operational_rows
    )
    items.sort(key=lambda item: item["created_at"], reverse=True)
    return {
        "items": items[:limit]
    }
