"""Federated hunt across OpenSearch + Qdrant + threat-intel exact/semantic."""

from __future__ import annotations

import logging
from typing import Any

import httpx
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from incident_api import opensearch_client
from incident_api.config import settings
from incident_api.embedding_client import embed_text
from incident_api.tenant import require_tenant

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/hunt", tags=["hunt"])


class FederatedHuntRequest(BaseModel):
    query: str = ""
    size: int = Field(default=50, ge=1, le=200)


def _normalize_os_hits(result: dict[str, Any], limit: int) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    for hit in ((result.get("hits") or {}).get("hits") or [])[:limit]:
        source = hit.get("_source") or {}
        hits.append(
            {
                "source": "opensearch",
                "id": hit.get("_id") or source.get("finding_id") or source.get("incident_id"),
                "title": source.get("title") or source.get("summary") or str(hit.get("_id")),
                "score": float(hit.get("_score") or 0.0),
                "summary": source.get("summary"),
            }
        )
    return hits


@router.post("/federated")
def federated_hunt(
    body: FederatedHuntRequest,
    tenant_id: str = Depends(require_tenant),
) -> dict[str, Any]:
    warnings: list[str] = []
    hits: list[dict[str, Any]] = []
    dependencies: dict[str, dict[str, Any]] = {}

    if not settings.federated_hunt_enabled and not settings.vector_search_enabled:
        # Still attempt OpenSearch-only for usability; warn about federation flags.
        warnings.append("FEDERATED_HUNT_ENABLED=false; returning OpenSearch results only")

    try:
        os_result = opensearch_client.search(
            tenant_id=tenant_id, query=body.query, size=body.size
        )
        hits.extend(_normalize_os_hits(os_result, body.size))
        dependencies["opensearch"] = {
            "status": "ready",
            "capability": "text_search",
            "reason": "query_completed",
        }
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"opensearch_unavailable: {exc}")
        dependencies["opensearch"] = {
            "status": "degraded",
            "capability": "text_search",
            "reason": str(exc),
            "retry_after_seconds": 5,
        }

    if settings.vector_search_enabled and settings.qdrant_url:
        try:
            from black_onyx_vector import VectorClient

            vector = embed_text(body.query)
            if vector is None:
                raise RuntimeError("embedding service unavailable or unconfigured")
            vc = VectorClient(url=settings.qdrant_url)
            if vc.available:
                for h in vc.search(
                    "findings_v1", vector, tenant_id, limit=min(10, body.size)
                ):
                    payload = h.get("payload") or {}
                    hits.append(
                        {
                            "source": "qdrant",
                            "id": payload.get("finding_id") or h.get("id"),
                            "title": payload.get("summary_text") or "vector neighbor",
                            "score": float(h.get("score") or 0.0),
                            "summary": payload.get("summary_text"),
                        }
                    )
                dependencies["vector_search"] = {
                    "status": "ready",
                    "capability": "vector_search",
                    "reason": "qdrant_and_embedding_service",
                }
            else:
                warnings.append("qdrant_unavailable")
                dependencies["vector_search"] = {
                    "status": "degraded",
                    "capability": "vector_search",
                    "reason": "qdrant_unavailable",
                    "retry_after_seconds": 5,
                }
        except Exception as exc:  # noqa: BLE001
            warnings.append(f"qdrant_error: {exc}")
            dependencies["vector_search"] = {
                "status": "degraded",
                "capability": "vector_search",
                "reason": str(exc),
                "retry_after_seconds": 5,
            }
    elif settings.federated_hunt_enabled:
        warnings.append("vector path skipped (VECTOR_SEARCH_ENABLED=false or QDRANT_URL empty)")
        dependencies["vector_search"] = {
            "status": "disabled",
            "capability": "vector_search",
            "reason": "VECTOR_SEARCH_ENABLED=false or QDRANT_URL empty",
        }
    else:
        dependencies["vector_search"] = {
            "status": "disabled",
            "capability": "vector_search",
            "reason": "federated vector hunt disabled",
        }

    ti_url = (settings.threat_intel_url or "").strip()
    if ti_url and body.query.strip():
        headers = {"X-Service-Key": settings.threat_intel_service_key or ""}
        obs = [{"type": "domain", "value": body.query.strip()}]
        try:
            with httpx.Client(timeout=5.0) as client:
                exact = client.post(
                    f"{ti_url.rstrip('/')}/api/v1/match",
                    json={"observables": obs},
                    headers=headers,
                )
                if exact.status_code == 200:
                    for m in exact.json().get("matches") or []:
                        hits.append(
                            {
                                "source": "ti_exact",
                                "id": m.get("id") or m.get("value"),
                                "title": f"Exact IOC {m.get('type')}:{m.get('value')}",
                                "score": float(m.get("confidence") or 1.0),
                                "summary": m.get("source"),
                            }
                        )
                semantic = client.post(
                    f"{ti_url.rstrip('/')}/api/v1/match/semantic",
                    json={"observables": obs},
                    headers=headers,
                )
                if semantic.status_code == 200:
                    body_s = semantic.json()
                    for w in body_s.get("warnings") or []:
                        warnings.append(str(w))
                    for m in body_s.get("matches") or []:
                        hits.append(
                            {
                                "source": "ti_semantic",
                                "id": m.get("id") or m.get("value"),
                                "title": f"Semantic IOC {m.get('type')}:{m.get('value')}",
                                "score": float(m.get("confidence") or 0.0),
                                "summary": m.get("source"),
                            }
                        )
                dependencies["threat_intelligence"] = {
                    "status": "ready",
                    "capability": "threat_intelligence",
                    "reason": "queries_completed",
                }
        except Exception as exc:  # noqa: BLE001
            warnings.append(f"threat_intel_unavailable: {exc}")
            dependencies["threat_intelligence"] = {
                "status": "degraded",
                "capability": "threat_intelligence",
                "reason": str(exc),
                "retry_after_seconds": 5,
            }
    else:
        dependencies["threat_intelligence"] = {
            "status": "disabled",
            "capability": "threat_intelligence",
            "reason": "THREAT_INTEL_URL empty or query empty",
        }

    hits.sort(key=lambda h: float(h.get("score") or 0.0), reverse=True)
    degraded = [
        name
        for name, state in dependencies.items()
        if state.get("status") == "degraded"
    ]
    return {
        "status": "degraded" if degraded else "ready",
        "capability": "federated_hunt",
        "reason": (
            f"degraded dependencies: {', '.join(degraded)}"
            if degraded
            else "available dependencies queried"
        ),
        "query": body.query,
        "tenant_id": tenant_id,
        "hits": hits[: body.size],
        "warnings": warnings,
        "dependencies": dependencies,
    }
