"""Optional Qdrant similarity helpers for findings/incidents/hunt."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from incident_api.config import settings
from incident_api.db import get_db
from incident_api.embedding_client import embed_text
from incident_api.models import FindingRow, IncidentRow
from incident_api.tenant import require_tenant

logger = logging.getLogger(__name__)
router = APIRouter(tags=["vector-search"])


class VectorHuntRequest(BaseModel):
    text: str = Field(min_length=1)
    collection: str = "findings_v1"
    limit: int = Field(default=10, ge=1, le=50)


def _client():
    if not settings.vector_search_enabled or not (settings.qdrant_url or "").strip():
        return None
    try:
        from black_onyx_vector import VectorClient

        client = VectorClient(url=settings.qdrant_url)
        return client if client.available else None
    except Exception as exc:  # noqa: BLE001
        logger.warning("vector client unavailable: %s", exc)
        return None


def _capability(
    status: str,
    reason: str,
    *,
    retry_after_seconds: int | None = None,
) -> dict[str, Any]:
    return {
        "status": status,
        "capability": "vector_search",
        "reason": reason,
        "retry_after_seconds": retry_after_seconds,
    }


@router.get("/api/v1/findings/{finding_id}/similar")
def similar_findings(
    finding_id: str,
    tenant_id: str = Depends(require_tenant),
    db: Session = Depends(get_db),
    limit: int = 10,
) -> dict[str, Any]:
    if not settings.vector_search_enabled:
        return {
            "items": [],
            **_capability("disabled", "VECTOR_SEARCH_ENABLED=false"),
        }
    row = db.scalar(
        select(FindingRow).where(
            FindingRow.tenant_id == tenant_id,
            FindingRow.finding_id == finding_id,
        )
    )
    if row is None:
        raise HTTPException(status_code=404, detail="finding not found")
    client = _client()
    if client is None:
        return {
            "items": [],
            **_capability("degraded", "qdrant_unavailable", retry_after_seconds=5),
        }
    try:
        hits = client.recommend("findings_v1", [finding_id], tenant_id, limit=limit)
    except Exception as exc:  # noqa: BLE001
        return {
            "items": [],
            **_capability("degraded", f"qdrant_recommend_failed: {exc}", retry_after_seconds=5),
        }
    items = [
        {
            "id": (h.get("payload") or {}).get("finding_id") or h.get("id"),
            "title": (h.get("payload") or {}).get("summary_text") or "similar finding",
            "score": h.get("score"),
            "source": "qdrant",
            "summary": (h.get("payload") or {}).get("summary_text"),
        }
        for h in hits
        if (h.get("payload") or {}).get("finding_id") != finding_id
    ]
    return {"items": items, **_capability("ready", "qdrant")}


@router.get("/api/v1/incidents/{incident_id}/similar")
def similar_incidents(
    incident_id: str,
    tenant_id: str = Depends(require_tenant),
    db: Session = Depends(get_db),
    limit: int = 10,
) -> dict[str, Any]:
    if not settings.vector_search_enabled:
        return {
            "items": [],
            **_capability("disabled", "VECTOR_SEARCH_ENABLED=false"),
        }
    row = db.scalar(
        select(IncidentRow).where(
            IncidentRow.tenant_id == tenant_id,
            IncidentRow.incident_id == incident_id,
        )
    )
    if row is None:
        raise HTTPException(status_code=404, detail="incident not found")
    client = _client()
    if client is None:
        return {
            "items": [],
            **_capability("degraded", "qdrant_unavailable", retry_after_seconds=5),
        }
    try:
        hits = client.recommend("incidents_v1", [incident_id], tenant_id, limit=limit)
    except Exception as exc:  # noqa: BLE001
        return {
            "items": [],
            **_capability("degraded", f"qdrant_recommend_failed: {exc}", retry_after_seconds=5),
        }
    items = [
        {
            "id": (h.get("payload") or {}).get("incident_id") or h.get("id"),
            "title": (h.get("payload") or {}).get("title") or "similar incident",
            "score": h.get("score"),
            "source": "qdrant",
        }
        for h in hits
        if (h.get("payload") or {}).get("incident_id") != incident_id
    ]
    return {"items": items, **_capability("ready", "qdrant")}


@router.post("/api/v1/hunt/vector")
def hunt_vector(
    body: VectorHuntRequest,
    tenant_id: str = Depends(require_tenant),
) -> dict[str, Any]:
    if not settings.vector_search_enabled:
        return {
            "hits": [],
            **_capability("disabled", "VECTOR_SEARCH_ENABLED=false"),
        }
    client = _client()
    if client is None:
        return {
            "hits": [],
            **_capability("degraded", "qdrant_unavailable", retry_after_seconds=5),
        }
    vector = embed_text(body.text)
    if vector is None:
        return {
            "hits": [],
            **_capability(
                "degraded",
                "embedding_service_unavailable_or_unconfigured",
                retry_after_seconds=5,
            ),
        }
    hits = client.search(
        body.collection,
        vector,
        tenant_id,
        limit=body.limit,
    )
    return {
        **_capability("ready", "qdrant_and_embedding_service"),
        "hits": [
            {
                "source": "qdrant",
                "id": (h.get("payload") or {}).get("finding_id")
                or (h.get("payload") or {}).get("incident_id")
                or h.get("id"),
                "title": (h.get("payload") or {}).get("summary_text")
                or (h.get("payload") or {}).get("title")
                or "vector hit",
                "score": h.get("score"),
                "payload": h.get("payload"),
            }
            for h in hits
        ]
    }
