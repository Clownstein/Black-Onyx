"""Idempotent deployment persistence shared by HTTP and Kafka ingestion."""

from __future__ import annotations

from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from incident_api.models import DeploymentEventRow, OperationalAuditRow
from incident_api.schemas import DeploymentEventCreate


def persist_deployment(
    db: Session,
    *,
    tenant_id: str,
    body: DeploymentEventCreate,
    actor: str,
) -> DeploymentEventRow:
    deployment_id = body.deployment_id or f"dep-{uuid4().hex[:16]}"
    row = db.scalar(
        select(DeploymentEventRow).where(
            DeploymentEventRow.tenant_id == tenant_id,
            DeploymentEventRow.deployment_id == deployment_id,
        )
    )
    payload = body.model_dump(mode="json", exclude={"deployment_id"})
    if row is None:
        row = DeploymentEventRow(
            deployment_id=deployment_id,
            tenant_id=tenant_id,
            service_id=body.service_id,
            environment=body.environment,
            commit_sha=body.commit_sha,
            version=body.version,
            status=body.status,
            deployed_at=body.deployed_at,
            payload=payload,
        )
        db.add(row)
    else:
        row.service_id = body.service_id
        row.environment = body.environment
        row.commit_sha = body.commit_sha
        row.version = body.version
        row.status = body.status
        row.deployed_at = body.deployed_at
        row.payload = payload
    db.add(
        OperationalAuditRow(
            tenant_id=tenant_id,
            resource_type="deployment",
            resource_id=deployment_id,
            action="deployment_upserted",
            actor=actor,
            detail={"service_id": body.service_id, "status": body.status},
        )
    )
    db.commit()
    db.refresh(row)
    return row
