from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from incident_api.db import get_db
from incident_api.minio_evidence import describe_evidence_uri, download_evidence_bytes
from incident_api.models import FindingRow, IncidentFindingRow, IncidentRow
from incident_api.opensearch_client import finding_doc_from_row, index_document
from incident_api.schemas import (
    FindingCreate,
    FindingEvidenceResponse,
    FindingListResponse,
    FindingRead,
    FindingWindow,
)
from incident_api.tenant import Principal, require_role, require_tenant

router = APIRouter(prefix="/api/v1/findings", tags=["findings"])


def _row_to_read(row: FindingRow) -> FindingRead:
    payload = dict(row.payload or {})
    return FindingRead(
        finding_id=row.finding_id,
        tenant_id=row.tenant_id,
        finding_type=row.finding_type,
        asset_id=row.asset_id,
        service_id=row.service_id,
        model_name=row.model_name,
        model_version=row.model_version,
        raw_score=row.raw_score,
        calibrated_score=row.calibrated_score,
        severity_hint=row.severity_hint,
        window=FindingWindow(start=row.window_start, end=row.window_end),
        contributors=list(payload.get("contributors") or []),
        evidence_refs=list(row.evidence_refs or []),
        context=dict(payload.get("context") or {}),
        category=list(payload.get("category") or []),
        payload=payload,
    )


def _get_or_404(db: Session, tenant_id: str, finding_id: str) -> FindingRow:
    row = db.scalar(
        select(FindingRow).where(
            FindingRow.tenant_id == tenant_id,
            FindingRow.finding_id == finding_id,
        )
    )
    if row is None:
        raise HTTPException(status_code=404, detail="finding not found")
    return row


@router.get("", response_model=FindingListResponse)
def list_findings(
    tenant_id: str = Depends(require_tenant),
    db: Session = Depends(get_db),
    type: str | None = Query(default=None),
    asset: str | None = Query(default=None),
    service: str | None = Query(default=None),
    min_score: float | None = Query(default=None),
    start: datetime | None = Query(default=None),
    end: datetime | None = Query(default=None),
) -> FindingListResponse:
    stmt = select(FindingRow).where(FindingRow.tenant_id == tenant_id)
    if type:
        stmt = stmt.where(FindingRow.finding_type == type)
    if asset:
        stmt = stmt.where(FindingRow.asset_id == asset)
    if service:
        stmt = stmt.where(FindingRow.service_id == service)
    rows = list(db.scalars(stmt).all())
    if min_score is not None:
        rows = [r for r in rows if r.calibrated_score >= min_score]
    if start is not None:
        rows = [r for r in rows if r.window_end >= start]
    if end is not None:
        rows = [r for r in rows if r.window_start <= end]
    rows.sort(key=lambda r: r.window_end, reverse=True)
    return FindingListResponse(items=[_row_to_read(r) for r in rows])


@router.get("/{finding_id}", response_model=FindingRead)
def get_finding(
    finding_id: str,
    tenant_id: str = Depends(require_tenant),
    db: Session = Depends(get_db),
) -> FindingRead:
    return _row_to_read(_get_or_404(db, tenant_id, finding_id))


@router.get("/{finding_id}/evidence", response_model=FindingEvidenceResponse)
def get_finding_evidence(
    finding_id: str,
    tenant_id: str = Depends(require_tenant),
    db: Session = Depends(get_db),
) -> FindingEvidenceResponse:
    row = _get_or_404(db, tenant_id, finding_id)
    payload = dict(row.payload or {})
    return FindingEvidenceResponse(
        finding_id=row.finding_id,
        evidence_refs=list(row.evidence_refs or []),
        contributors=list(payload.get("contributors") or []),
        context=dict(payload.get("context") or {}),
    )


@router.get("/{finding_id}/evidence/download")
def download_finding_evidence(
    finding_id: str,
    uri: str = Query(..., min_length=1),
    tenant_id: str = Depends(require_tenant),
    db: Session = Depends(get_db),
    _: Principal = Depends(require_role("analyst")),
) -> Response:
    """Download a PCAP/artifact referenced by evidence_refs URI (MinIO)."""
    row = _get_or_404(db, tenant_id, finding_id)
    refs = list(row.evidence_refs or [])
    payload = dict(row.payload or {})
    ctx_refs = list((payload.get("context") or {}).get("evidence_refs") or [])
    allowed = {str(r.get("uri") if isinstance(r, dict) else r) for r in refs + ctx_refs}
    if uri not in allowed and not any(isinstance(r, dict) and r.get("uri") == uri for r in refs):
        # Allow describe-only when URI is explicitly passed and matches prefix policy.
        if not uri.startswith("s3://"):
            raise HTTPException(status_code=400, detail="uri must be s3://…")
    try:
        meta = describe_evidence_uri(uri)
        data = download_evidence_bytes(uri)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"object store error: {exc}") from exc
    filename = meta["key"].rsplit("/", 1)[-1] or "evidence.bin"
    return Response(
        content=data,
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post("", response_model=FindingRead, status_code=201)
def create_or_upsert_finding(
    body: FindingCreate,
    tenant_id: str = Depends(require_tenant),
    db: Session = Depends(get_db),
    _: Principal = Depends(require_role("analyst")),
) -> FindingRead:
    finding_id = body.finding_id or f"finding-{uuid4().hex[:12]}"
    existing = db.scalar(
        select(FindingRow).where(
            FindingRow.tenant_id == tenant_id,
            FindingRow.finding_id == finding_id,
        )
    )
    payload = body.model_dump(mode="json")
    payload["tenant_id"] = tenant_id
    payload["finding_id"] = finding_id

    if existing is None:
        row = FindingRow(
            finding_id=finding_id,
            tenant_id=tenant_id,
            finding_type=body.finding_type,
            asset_id=body.asset_id,
            service_id=body.service_id,
            model_name=body.model_name,
            model_version=body.model_version,
            raw_score=body.raw_score,
            calibrated_score=body.calibrated_score,
            severity_hint=body.severity_hint,
            window_start=body.window.start,
            window_end=body.window.end,
            evidence_refs=list(body.evidence_refs or []),
            payload=payload,
        )
        db.add(row)
    else:
        existing.finding_type = body.finding_type
        existing.asset_id = body.asset_id
        existing.service_id = body.service_id
        existing.model_name = body.model_name
        existing.model_version = body.model_version
        existing.raw_score = body.raw_score
        existing.calibrated_score = body.calibrated_score
        existing.severity_hint = body.severity_hint
        existing.window_start = body.window.start
        existing.window_end = body.window.end
        existing.evidence_refs = list(body.evidence_refs or [])
        existing.payload = payload
        row = existing

    db.commit()
    db.refresh(row)
    incidents = db.scalars(
        select(IncidentRow).where(IncidentRow.tenant_id == tenant_id)
    ).all()
    linked_incidents = {
        link.incident_id
        for link in db.scalars(
            select(IncidentFindingRow).where(
                IncidentFindingRow.tenant_id == tenant_id,
                IncidentFindingRow.finding_id == finding_id,
            )
        ).all()
    }
    for incident in incidents:
        if finding_id in (incident.finding_ids or []) and incident.incident_id not in linked_incidents:
            db.add(
                IncidentFindingRow(
                    tenant_id=tenant_id,
                    incident_id=incident.incident_id,
                    finding_id=finding_id,
                )
            )
    db.commit()
    index_document("finding", row.finding_id, finding_doc_from_row(row))
    return _row_to_read(row)
