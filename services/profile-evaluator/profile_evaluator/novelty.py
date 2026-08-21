from __future__ import annotations

from typing import Any

import httpx

from profile_evaluator.config import settings

CONTRIBUTOR_NAME = "vector_novelty"


def _embedding(text: str) -> list[float] | None:
    base = (settings.embedding_service_url or "").strip()
    if not base:
        return None
    try:
        with httpx.Client(timeout=settings.http_timeout_sec) as client:
            response = client.post(
                f"{base.rstrip('/')}/api/v1/embed/text",
                json={"text": text},
            )
            response.raise_for_status()
            vector = response.json().get("vector")
            if isinstance(vector, list) and vector:
                return [float(value) for value in vector]
    except Exception:
        return None
    return None


def vector_novelty_score(
    enabled: bool,
    *,
    text: str = "",
    qdrant_url: str | None = None,
    tenant_id: str = "default",
) -> float:
    """Return real Qdrant novelty or zero when the capability is unavailable."""
    if not enabled:
        return 0.0
    vector = _embedding((text or "profile-evaluator-novelty").strip())
    if vector is None or not (qdrant_url or "").strip():
        return 0.0
    try:
        from black_onyx_vector import VectorClient

        client = VectorClient(url=str(qdrant_url))
        if not client.available:
            return 0.0
        hits = client.search(
            "features_baseline_v1",
            vector,
            tenant_id,
            vector_name="code",
            limit=5,
        )
        if not hits:
            return 0.0
        best = max(float(hit.get("score") or 0.0) for hit in hits)
        return round(max(0.0, min(1.0, 1.0 - best)), 4)
    except Exception:
        return 0.0


def vector_novelty_contributor(
    enabled: bool,
    *,
    text: str = "",
    qdrant_url: str | None = None,
    tenant_id: str = "default",
) -> dict[str, Any]:
    """Build a capability-aware finding contributor."""
    value = vector_novelty_score(
        enabled,
        text=text,
        qdrant_url=qdrant_url,
        tenant_id=tenant_id,
    )
    active = bool(enabled and value > 0.0)
    return {
        "name": CONTRIBUTOR_NAME,
        "enabled": bool(enabled),
        "active": active,
        "status": "ready" if active else ("disabled" if not enabled else "degraded"),
        "reason": None if active else (
            "disabled" if not enabled else "qdrant_or_embedding_service_unavailable"
        ),
        "value": value,
        "weight": 0.15 if active else 0.0,
    }
