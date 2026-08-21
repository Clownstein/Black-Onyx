"""Semantic (vector) observable matching.

This module provides an approximate, similarity-based match over stored
indicators. It is intentionally advisory: semantic hits carry a confidence
ceiling (``semantic_max_confidence``) and ``match_type="semantic"`` so callers
never treat a fuzzy hit as an exact indicator match.

Operating modes:

* ``vector_search_enabled=False`` (default): empty matches + warning.
* Enabled + ``qdrant_url``: query ``ti_text_v1`` via ``black_onyx_vector``.
* Enabled without both Qdrant and a real embedding service: degraded capability
  state with no fabricated matches.
"""

from __future__ import annotations

from typing import Any

import httpx
from sqlalchemy.orm import Session

from threat_intel_service.config import settings

_TLP_RANK = {"clear": 0, "white": 0, "green": 1, "amber": 2, "red": 3}


def _query_text(observables: list[dict[str, str]]) -> str:
    parts: list[str] = []
    for obs in observables:
        value = str(obs.get("value") or obs.get("observable_value") or "").strip()
        otype = str(obs.get("type") or obs.get("observable_type") or "").strip()
        if value:
            parts.append(value)
        if otype:
            parts.append(otype)
    return " ".join(parts)


def _embed_query(text: str) -> list[float] | None:
    base = (settings.embedding_service_url or "").strip()
    if not base:
        return None
    try:
        with httpx.Client(timeout=10.0) as client:
            response = client.post(
                f"{base.rstrip('/')}/api/v1/embed/text",
                json={"text": text},
            )
            response.raise_for_status()
            body = response.json()
            vector = body.get("vector")
            if isinstance(vector, list) and vector:
                return [float(value) for value in vector]
    except Exception:
        return None
    return None


def _match_from_qdrant(
    vector: list[float],
    *,
    qdrant_url: str,
    tenant_id: str,
    max_confidence: float,
    top_k: int,
    min_similarity: float,
) -> dict[str, Any] | None:
    try:
        from black_onyx_vector import VectorClient
    except ImportError:
        return None
    client = VectorClient(url=qdrant_url)
    if not client.available:
        return None
    try:
        # Threat intel is typically shared: include globally-tagged points.
        hits = client.search(
            "ti_text_v1", vector, tenant_id, limit=top_k, include_global=True
        )
    except Exception:
        return None
    matches: list[dict[str, Any]] = []
    campaigns: list[str] = []
    seen_campaigns: set[str] = set()
    best_rank = -1
    tlp: str | None = None
    for hit in hits:
        score = float(hit.get("score") or 0.0)
        if score < min_similarity:
            continue
        payload = hit.get("payload") or {}
        confidence = round(min(float(max_confidence), float(max_confidence) * score), 4)
        matches.append(
            {
                "id": payload.get("indicator_id") or hit.get("id"),
                "type": payload.get("observable_type") or payload.get("type") or "text",
                "value": payload.get("observable_value") or payload.get("text") or "",
                "confidence": confidence,
                "similarity": round(score, 4),
                "source": payload.get("source") or "qdrant",
                "tlp": payload.get("tlp"),
                "mitre_techniques": list(payload.get("mitre_techniques") or []),
                "match_type": "semantic",
            }
        )
        for camp in payload.get("campaigns") or []:
            if camp not in seen_campaigns:
                seen_campaigns.add(camp)
                campaigns.append(str(camp))
        if payload.get("tlp"):
            rank = _TLP_RANK.get(str(payload["tlp"]).lower(), -1)
            if rank > best_rank:
                best_rank = rank
                tlp = str(payload["tlp"])
    return {
        "status": "ready",
        "capability": "semantic_threat_intelligence",
        "reason": "qdrant_and_embedding_service",
        "match_type": "semantic",
        "vector_search_enabled": True,
        "matches": matches,
        "campaigns": campaigns,
        "tlp": tlp,
        "warnings": ["semantic_qdrant: results from ti_text_v1 are advisory"],
    }


def semantic_match(
    session: Session,
    observables: list[dict[str, str]],
    *,
    enabled: bool,
    max_confidence: float,
    top_k: int = 10,
    min_similarity: float = 0.1,
    qdrant_url: str | None = None,
    tenant_id: str = "default",
) -> dict[str, Any]:
    """Return semantic match result as a serializable dict."""
    warnings: list[str] = []
    if not enabled:
        warnings.append(
            "vector_search_disabled: set VECTOR_SEARCH_ENABLED=true to enable semantic matching"
        )
        return {
            "status": "disabled",
            "capability": "semantic_threat_intelligence",
            "reason": "VECTOR_SEARCH_ENABLED=false",
            "match_type": "semantic",
            "vector_search_enabled": False,
            "matches": [],
            "campaigns": [],
            "tlp": None,
            "warnings": warnings,
        }

    query_text = _query_text(observables)
    if not query_text.strip():
        return {
            "status": "ready",
            "capability": "semantic_threat_intelligence",
            "reason": "empty_query",
            "match_type": "semantic",
            "vector_search_enabled": True,
            "matches": [],
            "campaigns": [],
            "tlp": None,
            "warnings": ["empty_query: no observable values provided"],
        }

    vector = _embed_query(query_text)
    if vector is None:
        return {
            "status": "degraded",
            "capability": "semantic_threat_intelligence",
            "reason": "embedding_service_unavailable_or_unconfigured",
            "retry_after_seconds": 5,
            "match_type": "semantic",
            "vector_search_enabled": True,
            "matches": [],
            "campaigns": [],
            "tlp": None,
            "warnings": ["semantic matching unavailable; no fallback scores emitted"],
        }

    if qdrant_url and str(qdrant_url).strip():
        qdrant_result = _match_from_qdrant(
            vector,
            qdrant_url=str(qdrant_url).strip(),
            tenant_id=tenant_id,
            max_confidence=max_confidence,
            top_k=top_k,
            min_similarity=min_similarity,
        )
        if qdrant_result is not None:
            return qdrant_result
        warnings.append("qdrant_unavailable")
    return {
        "status": "degraded",
        "capability": "semantic_threat_intelligence",
        "reason": "qdrant_unavailable_or_unconfigured",
        "retry_after_seconds": 5,
        "match_type": "semantic",
        "vector_search_enabled": True,
        "matches": [],
        "campaigns": [],
        "tlp": None,
        "warnings": warnings,
    }


__all__ = ["semantic_match"]
