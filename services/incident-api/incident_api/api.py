from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from incident_api.db import get_db
from incident_api.models import (
    AnalystFeedbackRow,
    AuditRow,
    CommentRow,
    FindingRow,
    IncidentFindingRow,
    IncidentRow,
    TimelineRow,
)
from incident_api.opensearch_client import index_document, incident_doc_from_row
from incident_api.schemas import (
    CommentCreate,
    CommentRead,
    DispositionCreate,
    EvidenceItem,
    IncidentCreate,
    IncidentListResponse,
    IncidentPatch,
    IncidentRead,
    AnalystFeedbackCreate,
    AnalystFeedbackRead,
    TimelineEvent,
)
from incident_api.tenant import Principal, require_role, require_tenant

router = APIRouter(prefix="/api/v1/incidents", tags=["incidents"])


def _kind_from_finding_type(finding_type: str) -> str:
    t = finding_type.lower()
    if "log" in t:
        return "logs"
    if "net" in t or "flow" in t:
        return "network"
    if "metric" in t:
        return "metrics"
    if "code" in t:
        return "code"
    return "correlation"


def _evidence_from_findings(db: Session, tenant_id: str, finding_ids: list[str]) -> list[EvidenceItem]:
    if not finding_ids:
        return []
    rows = list(
        db.scalars(
            select(FindingRow).where(
                FindingRow.tenant_id == tenant_id,
                FindingRow.finding_id.in_(finding_ids),
            )
        ).all()
    )
    by_id = {r.finding_id: r for r in rows}
    items: list[EvidenceItem] = []
    for fid in finding_ids:
        row = by_id.get(fid)
        if row is None:
            continue
        payload = dict(row.payload or {})
        items.append(
            EvidenceItem(
                kind=_kind_from_finding_type(row.finding_type),
                model=row.model_name or "",
                title=str(payload.get("title") or f"{row.finding_type} on {row.asset_id}"),
                detail=str(
                    payload.get("summary")
                    or f"calibrated_score={row.calibrated_score:.3f}"
                ),
                score=row.calibrated_score,
                timestamp=row.window_end,
                raw={
                    "finding_id": row.finding_id,
                    "finding_type": row.finding_type,
                    "contributors": payload.get("contributors") or [],
                    "context": payload.get("context") or {},
                    "evidence_refs": row.evidence_refs or [],
                },
            )
        )
    return items


def _to_read(db: Session, row: IncidentRow) -> IncidentRead:
    evidence = [EvidenceItem.model_validate(e) for e in (row.evidence or [])]
    if not evidence:
        evidence = _evidence_from_findings(db, row.tenant_id, list(row.finding_ids or []))
    return IncidentRead(
        incident_id=row.incident_id,
        tenant_id=row.tenant_id,
        title=row.title,
        status=row.status,
        severity=row.severity,
        risk_score=row.risk_score,
        category=list(row.category or []),
        first_seen=row.first_seen,
        last_seen=row.last_seen,
        assets=list(row.assets or []),
        services=list(row.services or []),
        finding_ids=list(row.finding_ids or []),
        summary=row.summary,
        disposition=row.disposition,
        assigned_to=row.assigned_to,
        models=list(row.models or []),
        deployment_id=row.deployment_id,
        commit=row.commit,
        evidence=evidence,
        context=dict(row.context or {}),
        fingerprint=row.fingerprint,
    )


def _get_or_404(db: Session, tenant_id: str, incident_id: str) -> IncidentRow:
    row = db.scalar(
        select(IncidentRow).where(
            IncidentRow.tenant_id == tenant_id,
            IncidentRow.incident_id == incident_id,
        )
    )
    if row is None:
        raise HTTPException(status_code=404, detail="incident not found")
    return row


def _timeline(
    db: Session,
    tenant_id: str,
    incident_id: str,
    event_type: str,
    summary: str,
    detail: dict,
    *,
    actor: str | None = None,
    occurred_at: datetime | None = None,
) -> None:
    db.add(
        TimelineRow(
            entry_id=f"tl-{uuid4().hex[:16]}",
            tenant_id=tenant_id,
            incident_id=incident_id,
            event_type=event_type,
            summary=summary,
            detail=detail,
            actor=actor,
            occurred_at=occurred_at or datetime.now(timezone.utc),
        )
    )


def _audit(
    db: Session,
    tenant_id: str,
    incident_id: str,
    action: str,
    detail: dict,
    *,
    actor: str | None = None,
) -> None:
    db.add(
        AuditRow(
            tenant_id=tenant_id,
            incident_id=incident_id,
            action=action,
            detail=detail,
        )
    )
    _timeline(
        db,
        tenant_id,
        incident_id,
        action,
        str(detail.get("summary") or action.replace("_", " ").title()),
        detail,
        actor=actor,
    )


def _sync_finding_links(
    db: Session,
    tenant_id: str,
    incident_id: str,
    finding_ids: list[str],
) -> None:
    db.execute(
        delete(IncidentFindingRow).where(
            IncidentFindingRow.tenant_id == tenant_id,
            IncidentFindingRow.incident_id == incident_id,
        )
    )
    if not finding_ids:
        return
    existing_ids = set(
        db.scalars(
            select(FindingRow.finding_id).where(
                FindingRow.tenant_id == tenant_id,
                FindingRow.finding_id.in_(set(finding_ids)),
            )
        ).all()
    )
    for finding_id in dict.fromkeys(finding_ids):
        if finding_id in existing_ids:
            db.add(
                IncidentFindingRow(
                    tenant_id=tenant_id,
                    incident_id=incident_id,
                    finding_id=finding_id,
                )
            )


@router.get("", response_model=IncidentListResponse)
def list_incidents(
    tenant_id: str = Depends(require_tenant),
    db: Session = Depends(get_db),
    status: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    service: str | None = Query(default=None),
    min_score: float | None = Query(default=None),
    site_id: str | None = Query(default=None),
) -> IncidentListResponse:
    stmt = select(IncidentRow).where(IncidentRow.tenant_id == tenant_id)
    if status:
        stmt = stmt.where(IncidentRow.status == status)
    if severity:
        stmt = stmt.where(IncidentRow.severity == severity)
    rows = list(db.scalars(stmt).all())
    if service:
        rows = [r for r in rows if service in (r.services or [])]
    if min_score is not None:
        rows = [r for r in rows if r.risk_score >= min_score]
    if site_id:
        rows = [r for r in rows if str((r.context or {}).get("site_id") or "") == site_id]
    rows.sort(key=lambda r: r.last_seen, reverse=True)
    return IncidentListResponse(
        items=[_to_read(db, row) for row in rows],
        next_cursor=None,
    )


@router.post("", response_model=IncidentRead, status_code=201)
def create_incident(
    body: IncidentCreate,
    tenant_id: str = Depends(require_tenant),
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_role("analyst")),
) -> IncidentRead:
    incident_id = body.incident_id or f"inc-{uuid4().hex[:12]}"
    existing = db.scalar(
        select(IncidentRow).where(
            IncidentRow.tenant_id == tenant_id,
            IncidentRow.incident_id == incident_id,
        )
    )
    evidence = [e.model_dump(mode="json") for e in body.evidence]
    if existing is not None:
        # Upsert findings / scores for correlation updates
        existing.title = body.title
        existing.status = body.status
        existing.severity = body.severity
        existing.risk_score = body.risk_score
        existing.category = body.category
        existing.last_seen = body.last_seen
        existing.assets = body.assets
        existing.services = body.services
        existing.finding_ids = body.finding_ids
        existing.summary = body.summary
        existing.models = body.models
        existing.deployment_id = body.deployment_id
        existing.commit = body.commit
        existing.evidence = evidence
        existing.context = body.context
        existing.fingerprint = body.fingerprint
        _sync_finding_links(db, tenant_id, incident_id, body.finding_ids)
        _audit(
            db,
            tenant_id,
            incident_id,
            "updated",
            {"risk_score": body.risk_score},
            actor=principal.subject,
        )
        db.commit()
        db.refresh(existing)
        index_document("incident", existing.incident_id, incident_doc_from_row(existing))
        return _to_read(db, existing)

    row = IncidentRow(
        incident_id=incident_id,
        tenant_id=tenant_id,
        title=body.title,
        status=body.status,
        severity=body.severity,
        risk_score=body.risk_score,
        category=body.category,
        first_seen=body.first_seen,
        last_seen=body.last_seen,
        assets=body.assets,
        services=body.services,
        finding_ids=body.finding_ids,
        summary=body.summary,
        disposition=body.disposition,
        assigned_to=body.assigned_to,
        models=body.models,
        deployment_id=body.deployment_id,
        commit=body.commit,
        evidence=evidence,
        context=body.context,
        fingerprint=body.fingerprint,
    )
    db.add(row)
    db.flush()
    _sync_finding_links(db, tenant_id, incident_id, body.finding_ids)
    _timeline(
        db,
        tenant_id,
        incident_id,
        "incident_opened",
        body.title,
        {"severity": body.severity, "risk_score": body.risk_score},
        actor=principal.subject,
        occurred_at=body.first_seen,
    )
    _audit(
        db,
        tenant_id,
        incident_id,
        "created",
        {"severity": body.severity},
        actor=principal.subject,
    )
    db.commit()
    db.refresh(row)
    index_document("incident", row.incident_id, incident_doc_from_row(row))
    return _to_read(db, row)


@router.get("/{incident_id}", response_model=IncidentRead)
def get_incident(
    incident_id: str,
    tenant_id: str = Depends(require_tenant),
    db: Session = Depends(get_db),
) -> IncidentRead:
    return _to_read(db, _get_or_404(db, tenant_id, incident_id))


@router.patch("/{incident_id}", response_model=IncidentRead)
def patch_incident(
    incident_id: str,
    body: IncidentPatch,
    tenant_id: str = Depends(require_tenant),
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_role("analyst")),
) -> IncidentRead:
    row = _get_or_404(db, tenant_id, incident_id)
    data = body.model_dump(exclude_unset=True)
    for key, value in data.items():
        setattr(row, key, value)
    if "finding_ids" in data and data["finding_ids"] is not None:
        _sync_finding_links(db, tenant_id, incident_id, list(data["finding_ids"]))
    _audit(db, tenant_id, incident_id, "patched", data, actor=principal.subject)
    db.commit()
    db.refresh(row)
    index_document("incident", row.incident_id, incident_doc_from_row(row))
    return _to_read(db, row)


@router.get("/{incident_id}/comments", response_model=list[CommentRead])
def list_comments(
    incident_id: str,
    tenant_id: str = Depends(require_tenant),
    db: Session = Depends(get_db),
) -> list[CommentRead]:
    _get_or_404(db, tenant_id, incident_id)
    rows = list(
        db.scalars(
            select(CommentRow)
            .where(
                CommentRow.tenant_id == tenant_id,
                CommentRow.incident_id == incident_id,
            )
            .order_by(CommentRow.created_at.asc())
        ).all()
    )
    return [CommentRead.model_validate(r) for r in rows]


@router.post("/{incident_id}/comments", response_model=CommentRead, status_code=201)
def add_comment(
    incident_id: str,
    body: CommentCreate,
    tenant_id: str = Depends(require_tenant),
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_role("analyst")),
) -> CommentRead:
    _get_or_404(db, tenant_id, incident_id)
    comment = CommentRow(
        comment_id=f"cmt-{uuid4().hex[:12]}",
        tenant_id=tenant_id,
        incident_id=incident_id,
        author=principal.subject,
        body=body.body,
    )
    db.add(comment)
    _audit(
        db,
        tenant_id,
        incident_id,
        "comment",
        {"comment_id": comment.comment_id, "summary": "Analyst comment added"},
        actor=principal.subject,
    )
    db.commit()
    db.refresh(comment)
    return CommentRead.model_validate(comment)


@router.post("/{incident_id}/disposition", response_model=IncidentRead)
def set_disposition(
    incident_id: str,
    body: DispositionCreate,
    tenant_id: str = Depends(require_tenant),
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_role("analyst")),
) -> IncidentRead:
    row = _get_or_404(db, tenant_id, incident_id)
    row.disposition = body.disposition
    if row.status == "open":
        row.status = "resolved"
    _audit(
        db,
        tenant_id,
        incident_id,
        "disposition",
        {"disposition": body.disposition, "note": body.note},
        actor=principal.subject,
    )
    db.commit()
    db.refresh(row)
    return _to_read(db, row)


@router.get("/{incident_id}/timeline", response_model=list[TimelineEvent])
def timeline(
    incident_id: str,
    tenant_id: str = Depends(require_tenant),
    db: Session = Depends(get_db),
) -> list[TimelineEvent]:
    _get_or_404(db, tenant_id, incident_id)
    rows = list(
        db.scalars(
            select(TimelineRow)
            .where(
                TimelineRow.tenant_id == tenant_id,
                TimelineRow.incident_id == incident_id,
            )
            .order_by(TimelineRow.occurred_at.asc(), TimelineRow.id.asc())
        ).all()
    )
    return [
        TimelineEvent(
            entry_id=row.entry_id,
            occurred_at=row.occurred_at,
            event_type=row.event_type,
            summary=row.summary,
            refs=dict(row.detail or {}),
            actor=row.actor,
        )
        for row in rows
    ]


@router.get("/{incident_id}/feedback", response_model=list[AnalystFeedbackRead])
def list_feedback(
    incident_id: str,
    tenant_id: str = Depends(require_tenant),
    db: Session = Depends(get_db),
) -> list[AnalystFeedbackRead]:
    _get_or_404(db, tenant_id, incident_id)
    rows = list(
        db.scalars(
            select(AnalystFeedbackRow)
            .where(
                AnalystFeedbackRow.tenant_id == tenant_id,
                AnalystFeedbackRow.incident_id == incident_id,
            )
            .order_by(AnalystFeedbackRow.created_at.asc())
        ).all()
    )
    return [AnalystFeedbackRead.model_validate(row) for row in rows]


@router.post(
    "/{incident_id}/feedback",
    response_model=AnalystFeedbackRead,
    status_code=201,
)
def add_feedback(
    incident_id: str,
    body: AnalystFeedbackCreate,
    tenant_id: str = Depends(require_tenant),
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_role("analyst")),
) -> AnalystFeedbackRead:
    _get_or_404(db, tenant_id, incident_id)
    if body.finding_id:
        finding = db.scalar(
            select(FindingRow).where(
                FindingRow.tenant_id == tenant_id,
                FindingRow.finding_id == body.finding_id,
            )
        )
        if finding is None:
            raise HTTPException(status_code=400, detail="finding does not belong to tenant")
    row = AnalystFeedbackRow(
        feedback_id=f"fb-{uuid4().hex[:16]}",
        tenant_id=tenant_id,
        incident_id=incident_id,
        finding_id=body.finding_id,
        label=body.label,
        note=body.note,
        actor=principal.subject,
    )
    db.add(row)
    _audit(
        db,
        tenant_id,
        incident_id,
        "analyst_feedback",
        {
            "feedback_id": row.feedback_id,
            "label": body.label,
            "finding_id": body.finding_id,
            "summary": f"Analyst feedback: {body.label}",
        },
        actor=principal.subject,
    )
    db.commit()
    db.refresh(row)
    return AnalystFeedbackRead.model_validate(row)


@router.get("/{incident_id}/related", response_model=IncidentListResponse)
def related(
    incident_id: str,
    tenant_id: str = Depends(require_tenant),
    db: Session = Depends(get_db),
) -> IncidentListResponse:
    row = _get_or_404(db, tenant_id, incident_id)
    others = list(
        db.scalars(
            select(IncidentRow).where(
                IncidentRow.tenant_id == tenant_id,
                IncidentRow.incident_id != incident_id,
            )
        ).all()
    )
    related_rows = [
        r
        for r in others
        if set(r.assets or []) & set(row.assets or [])
        or set(r.services or []) & set(row.services or [])
    ]
    return IncidentListResponse(items=[_to_read(db, r) for r in related_rows])


@router.get("/{incident_id}/runbooks")
def incident_runbooks(
    incident_id: str,
    tenant_id: str = Depends(require_tenant),
    db: Session = Depends(get_db),
) -> dict:
    """Retrieve-only runbook suggestions (RAG when vectors enabled; curated fallback)."""
    _get_or_404(db, tenant_id, incident_id)
    from incident_api.config import settings

    if not settings.vector_search_enabled:
        return {
            "items": [],
            "status": "disabled",
            "capability": "runbook_vector_search",
            "reason": "VECTOR_SEARCH_ENABLED=false",
            "vector_search_enabled": False,
        }
    if settings.vector_search_enabled and settings.qdrant_url:
        try:
            from black_onyx_vector import VectorClient
            from incident_api.vector_api import _embed_text

            row = _get_or_404(db, tenant_id, incident_id)
            text = row.summary or row.title or incident_id
            vector = _embed_text(text)
            vc = VectorClient(url=settings.qdrant_url)
            if vc.available and vector is not None:
                hits = vc.search(
                    "runbooks_v1",
                    vector,
                    tenant_id,
                    limit=5,
                )
                if hits:
                    return {
                        "status": "ready",
                        "capability": "runbook_vector_search",
                        "items": [
                            {
                                "title": (h.get("payload") or {}).get("title") or "runbook",
                                "path": (h.get("payload") or {}).get("path") or "",
                                "score": float(h.get("score") or 0.0),
                            }
                            for h in hits
                        ]
                    }
        except Exception as exc:
            return {
                "items": [],
                "status": "degraded",
                "capability": "runbook_vector_search",
                "reason": str(exc),
                "retry_after_seconds": 5,
            }
    return {
        "items": [],
        "status": "degraded",
        "capability": "runbook_vector_search",
        "reason": "qdrant_or_embedding_service_unavailable",
        "retry_after_seconds": 5,
    }
