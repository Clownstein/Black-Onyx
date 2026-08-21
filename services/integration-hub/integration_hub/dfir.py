"""Velociraptor DFIR collection queue with optional live submission."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

from sqlalchemy.orm import Session

from integration_hub.adapters import velociraptor_collect
from integration_hub.models import DfirCollectRequest


def queue_collect(
    db: Session,
    *,
    tenant_id: str,
    asset_id: str,
    artifact: str = "Generic.Client.Info",
    incident_id: str | None = None,
    dry_run: bool = True,
    detail: dict[str, Any] | None = None,
    notes: str | None = None,
) -> DfirCollectRequest:
    request_id = f"dfir-{uuid4().hex[:12]}"
    submission = velociraptor_collect(
        asset_id=asset_id,
        artifact=artifact,
        dry_run=dry_run,
        detail=detail,
    )
    status = str(submission.get("status") or "queued")
    merged_detail = dict(detail or {})
    merged_detail["submission"] = submission

    row = DfirCollectRequest(
        request_id=request_id,
        tenant_id=tenant_id,
        incident_id=incident_id,
        asset_id=asset_id,
        artifact=artifact,
        status=status,
        dry_run=dry_run,
        detail=merged_detail,
        notes=notes,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row
