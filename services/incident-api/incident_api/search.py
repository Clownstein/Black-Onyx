from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from incident_api.db import get_db
from incident_api.models import FindingRow, IncidentRow
from incident_api.schemas import SearchHit, SearchRequest, SearchResponse
from incident_api.tenant import require_tenant

router = APIRouter(prefix="/api/v1", tags=["search"])


def _matches(query: str, *parts: str | None) -> bool:
    q = query.strip().lower()
    if not q:
        return True
    haystack = " ".join(p for p in parts if p).lower()
    tokens = [t for t in q.replace(":", " ").split() if t]
    return all(token in haystack for token in tokens)


@router.post("/search", response_model=SearchResponse)
def search(
    body: SearchRequest,
    tenant_id: str = Depends(require_tenant),
    db: Session = Depends(get_db),
) -> SearchResponse:
    wanted = {t.lower() for t in body.types} or {"incident", "finding"}
    hits: list[SearchHit] = []

    if "incident" in wanted or "incidents" in wanted:
        incidents = list(
            db.scalars(select(IncidentRow).where(IncidentRow.tenant_id == tenant_id)).all()
        )
        for row in incidents:
            if _matches(body.query, row.title, row.summary, row.severity, " ".join(row.services or [])):
                hits.append(
                    SearchHit(
                        type="incident",
                        id=row.incident_id,
                        title=row.title,
                        summary=row.summary,
                        score=row.risk_score,
                        refs={"severity": row.severity, "status": row.status},
                    )
                )

    if "finding" in wanted or "findings" in wanted:
        findings = list(
            db.scalars(select(FindingRow).where(FindingRow.tenant_id == tenant_id)).all()
        )
        for row in findings:
            title = f"{row.finding_type} on {row.asset_id}"
            summary = str((row.payload or {}).get("summary") or row.model_name)
            if _matches(
                body.query,
                title,
                summary,
                row.finding_type,
                row.asset_id,
                row.service_id,
                row.model_name,
            ):
                hits.append(
                    SearchHit(
                        type="finding",
                        id=row.finding_id,
                        title=title,
                        summary=summary,
                        score=row.calibrated_score,
                        refs={
                            "finding_type": row.finding_type,
                            "asset_id": row.asset_id,
                            "service_id": row.service_id,
                        },
                    )
                )

    hits.sort(key=lambda h: h.score if h.score is not None else 0.0, reverse=True)
    return SearchResponse(items=hits[: body.limit])
