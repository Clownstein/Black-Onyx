from __future__ import annotations

import base64
import binascii
import json
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


def _row_to_read(row: FindingRow, incident_ids: list[str] | None = None) -> FindingRead:
    payload = dict(row.payload or {})
    return FindingRead(
        finding_id=row.finding_id,
        incident_ids=incident_ids or [],
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


def _evidence_uri(value: Any) -> str | None:
    uri = value.get("uri") if isinstance(value, dict) else value
    return str(uri) if isinstance(uri, str) and uri.strip() else None


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


def _linked_incidents(db: Session, tenant_id: str, finding_ids: list[str]) -> dict[str, list[str]]:
    if not finding_ids:
        return {}
    links = db.scalars(
        select(IncidentFindingRow).where(
            IncidentFindingRow.tenant_id == tenant_id,
            IncidentFindingRow.finding_id.in_(finding_ids),
        )
    ).all()
    result: dict[str, list[str]] = {finding_id: [] for finding_id in finding_ids}
    for link in links:
        result.setdefault(link.finding_id, []).append(link.incident_id)
    for values in result.values():
        values.sort()
    return result


def _decode_cursor(cursor: str) -> tuple[datetime, str]:
    try:
        raw = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4))
        value = json.loads(raw)
        if not isinstance(value, list) or len(value) != 2:
            raise ValueError
        timestamp = datetime.fromisoformat(str(value[0]))
        return timestamp, str(value[1])
    except (ValueError, TypeError, json.JSONDecodeError, UnicodeDecodeError, binascii.Error):
        raise HTTPException(status_code=400, detail="invalid findings cursor") from None


def _encode_cursor(row: FindingRow) -> str:
    raw = json.dumps([row.window_end.isoformat(), row.finding_id], separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


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
    cursor: str | None = Query(default=None, max_length=1024),
    limit: int = Query(default=100, ge=1, le=500),
) -> FindingListResponse:
    stmt = select(FindingRow).where(FindingRow.tenant_id == tenant_id)
    if type:
        stmt = stmt.where(FindingRow.finding_type == type)
    if asset:
        stmt = stmt.where(FindingRow.asset_id == asset)
    if service:
        stmt = stmt.where(FindingRow.service_id == service)
    if min_score is not None:
        stmt = stmt.where(FindingRow.calibrated_score >= min_score)
    if start is not None:
        stmt = stmt.where(FindingRow.window_end >= start)
    if end is not None:
        stmt = stmt.where(FindingRow.window_start <= end)
    if cursor:
        cursor_time, cursor_id = _decode_cursor(cursor)
        stmt = stmt.where(
            (FindingRow.window_end < cursor_time)
            | ((FindingRow.window_end == cursor_time) & (FindingRow.finding_id < cursor_id))
        )
    stmt = stmt.order_by(FindingRow.window_end.desc(), FindingRow.finding_id.desc()).limit(limit + 1)
    rows = list(db.scalars(stmt).all())
    has_more = len(rows) > limit
    rows = rows[:limit]
    links = _linked_incidents(db, tenant_id, [row.finding_id for row in rows])
    return FindingListResponse(
        items=[_row_to_read(row, links.get(row.finding_id, [])) for row in rows],
        next_cursor=_encode_cursor(rows[-1]) if has_more and rows else None,
    )


@router.get("/{finding_id}", response_model=FindingRead)
def get_finding(
    finding_id: str,
    tenant_id: str = Depends(require_tenant),
    db: Session = Depends(get_db),
) -> FindingRead:
    row = _get_or_404(db, tenant_id, finding_id)
    links = _linked_incidents(db, tenant_id, [finding_id])
    return _row_to_read(row, links.get(finding_id, []))


@router.get("/{finding_id}/evidence", response_model=FindingEvidenceResponse)
def get_finding_evidence(
    finding_id: str,
    tenant_id: str = Depends(require_tenant),
    db: Session = Depends(get_db),
) -> FindingEvidenceResponse:
    row = _get_or_404(db, tenant_id, finding_id)
    payload = dict(row.payload or {})
    context = dict(payload.get("context") or {})
    refs = list(row.evidence_refs or []) + list(context.get("evidence_refs") or [])
    evidence_refs = list(dict.fromkeys(uri for item in refs if (uri := _evidence_uri(item))))
    return FindingEvidenceResponse(
        finding_id=row.finding_id,
        evidence_refs=evidence_refs,
        contributors=list(payload.get("contributors") or []),
        context=context,
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
    if uri not in allowed:
        raise HTTPException(status_code=403, detail="evidence is not referenced by this finding")
    try:
        meta = describe_evidence_uri(uri, tenant_id)
        data = download_evidence_bytes(uri, tenant_id)
    except ValueError as exc:
        status = 413 if "size limit" in str(exc) else 403
        raise HTTPException(status_code=status, detail=str(exc)) from None
    except RuntimeError:
        raise HTTPException(status_code=503, detail="evidence storage is unavailable") from None
    except Exception:  # noqa: BLE001 - do not expose object-store errors
        raise HTTPException(status_code=502, detail="evidence download failed") from None
    return Response(
        content=data,
        media_type="application/octet-stream",
        headers={"Content-Disposition": meta["content_disposition"]},
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
