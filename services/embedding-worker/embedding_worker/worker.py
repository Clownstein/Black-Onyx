"""Embed findings and upsert them into the Qdrant ``findings_v1`` collection.

All vector operations are best-effort: when ``VECTOR_SEARCH_ENABLED`` is false,
``qdrant-client`` is unavailable, or Qdrant is down, findings are skipped with a
``status`` reason rather than raising, so the platform keeps running unchanged.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from embedding_worker.config import settings
from embedding_worker.embed import EmbeddingUnavailableError, embedder

logger = logging.getLogger(__name__)

try:  # soft import so the service runs even if the shared package is missing
    from black_onyx_vector import VectorClient, has_qdrant
except Exception:  # noqa: BLE001
    VectorClient = None  # type: ignore[assignment]

    def has_qdrant() -> bool:  # type: ignore[misc]
        return False


_client: Any | None = None
_collections_ready = False


def _iso_to_ts(value: Any) -> int:
    if not value:
        return int(datetime.now(UTC).timestamp())
    try:
        text = str(value).replace("Z", "+00:00")
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return int(dt.timestamp())
    except ValueError:
        return int(datetime.now(UTC).timestamp())


def vector_client() -> Any | None:
    """Return a cached VectorClient, or None when vector search is disabled."""

    global _client
    if not settings.vector_search_enabled:
        return None
    if VectorClient is None or not has_qdrant():
        return None
    if _client is None:
        _client = VectorClient(
            url=settings.qdrant_url,
            api_key=settings.qdrant_api_key or None,
        )
    return _client if _client.available else None


def ensure_collections() -> bool:
    """Best-effort collection provisioning. Returns True when collections exist."""

    global _collections_ready
    client = vector_client()
    if client is None:
        return False
    try:
        client.ensure_collections([settings.findings_collection])
        _collections_ready = True
    except Exception as exc:  # noqa: BLE001
        logger.warning("qdrant ensure_collections failed: %s", exc)
        _collections_ready = False
    return _collections_ready


def _summary_text(finding: dict[str, Any]) -> str:
    for key in ("summary_text", "summary", "title"):
        val = finding.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()
    ctx = finding.get("context") or {}
    if isinstance(ctx, dict):
        val = ctx.get("summary") or ctx.get("description")
        if isinstance(val, str) and val.strip():
            return val.strip()
    parts = [
        str(finding.get("finding_type") or "finding"),
        str(finding.get("asset_id") or ""),
        str(finding.get("service_id") or ""),
    ]
    return " ".join(p for p in parts if p).strip() or "finding"


def build_finding_payload(finding: dict[str, Any]) -> dict[str, Any]:
    """Build a ``findings_v1`` payload from a finding envelope/dict."""

    window = finding.get("window") or {}
    occurred_at = (
        finding.get("occurred_at")
        or (window.get("end") if isinstance(window, dict) else None)
        or datetime.now(UTC).isoformat().replace("+00:00", "Z")
    )
    context = finding.get("context") if isinstance(finding.get("context"), dict) else {}
    payload: dict[str, Any] = {
        "tenant_id": str(finding["tenant_id"]),
        "finding_id": str(finding["finding_id"]),
        "finding_type": str(finding.get("finding_type") or "unknown"),
        "asset_id": str(finding.get("asset_id") or "unknown"),
        "calibrated_score": float(finding.get("calibrated_score") or 0.0),
        "occurred_at": str(occurred_at),
        "occurred_at_ts": _iso_to_ts(occurred_at),
        "embed_model": settings.embed_model,
        "embed_version": settings.embed_version,
        "summary_text": _summary_text(finding),
        "schema_version": "1.0",
    }
    if finding.get("service_id"):
        payload["service_id"] = str(finding["service_id"])
    if finding.get("site_id"):
        payload["site_id"] = str(finding["site_id"])
    if finding.get("model_name"):
        payload["model_name"] = str(finding["model_name"])
    if finding.get("severity_hint"):
        payload["severity_hint"] = str(finding["severity_hint"])
    if finding.get("incident_id"):
        payload["incident_id"] = str(finding["incident_id"])
    modality = finding.get("modality") or context.get("modality")
    if modality:
        payload["modality"] = str(modality)
    for key in ("mitre_tactics", "mitre_techniques"):
        vals = finding.get(key) or context.get(key)
        if isinstance(vals, list) and vals:
            payload[key] = [str(v) for v in vals]
    contributors = finding.get("contributors")
    if isinstance(contributors, list) and contributors:
        types = [
            str(c.get("type")) for c in contributors if isinstance(c, dict) and c.get("type")
        ]
        if types:
            payload["contributor_types"] = types
    return payload


def process_finding(finding: dict[str, Any]) -> dict[str, Any]:
    """Embed a single finding and upsert it. Never raises on soft failures."""

    if not isinstance(finding, dict):
        return {"status": "skipped", "reason": "not_a_dict"}
    if not finding.get("tenant_id") or not finding.get("finding_id"):
        return {"status": "skipped", "reason": "missing_tenant_or_finding_id"}

    if not settings.vector_search_enabled:
        return {"status": "disabled", "reason": "vector_search_disabled"}

    client = vector_client()
    if client is None:
        return {"status": "unavailable", "reason": "qdrant_client_unavailable"}

    if not _collections_ready:
        ensure_collections()

    payload = build_finding_payload(finding)
    try:
        vector = embedder.embed(payload["summary_text"])
    except EmbeddingUnavailableError as exc:
        return {
            "status": "degraded",
            "capability": "text_embedding",
            "reason": str(exc),
            "retry_after_seconds": 30,
            "finding_id": payload["finding_id"],
        }
    point = {
        "id": payload["finding_id"],
        "vector": {"dense": vector},
        "payload": payload,
    }
    try:
        client.upsert(settings.findings_collection, [point], wait=True)
    except Exception as exc:  # noqa: BLE001 - soft-fail if Qdrant is down
        logger.warning("qdrant upsert failed for %s: %s", payload["finding_id"], exc)
        return {
            "status": "degraded",
            "capability": "vector_storage",
            "reason": str(exc),
            "retry_after_seconds": 30,
            "finding_id": payload["finding_id"],
        }
    return {
        "status": "upserted",
        "finding_id": payload["finding_id"],
        "collection": settings.findings_collection,
        "dim": len(vector),
    }
