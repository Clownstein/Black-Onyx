"""OpenSearch hunt proxy (tenant-scoped)."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query

from incident_api import opensearch_client
from incident_api.tenant import require_tenant

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/hunt", tags=["hunt"])


@router.get("/search")
def hunt_search(
    q: str = Query(default="", description="Free-text hunt query"),
    size: int = Query(default=50, ge=1, le=200),
    tenant_id: str = Depends(require_tenant),
) -> dict[str, Any]:
    """Proxy OpenSearch `_search` over `aa-findings-*` / `aa-incidents-*` with tenant filter.

    Prefer OpenSearch Dashboards or Grafana OpenSearch panels for complex hunts;
    this endpoint is a thin authenticated proxy for ops console / scripts.
    """
    try:
        result = opensearch_client.search(tenant_id=tenant_id, query=q, size=size)
    except Exception as exc:  # noqa: BLE001
        logger.warning("hunt search failed tenant=%s: %s", tenant_id, exc)
        raise HTTPException(
            status_code=502,
            detail=f"OpenSearch hunt unavailable: {exc}",
        ) from exc

    hits = []
    for hit in (result.get("hits") or {}).get("hits") or []:
        source = hit.get("_source") or {}
        hits.append(
            {
                "index": hit.get("_index"),
                "id": hit.get("_id"),
                "score": hit.get("_score"),
                "source": source,
            }
        )
    return {
        "query": q,
        "tenant_id": tenant_id,
        "total": ((result.get("hits") or {}).get("total") or {}).get("value"),
        "hits": hits,
    }
