"""Best-effort OpenSearch indexing for hunt plane (findings / incidents)."""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

import httpx

from incident_api.config import settings

logger = logging.getLogger(__name__)

FINDINGS_INDEX = "aa-findings"
INCIDENTS_INDEX = "aa-incidents"


def _client(**kwargs: Any) -> httpx.Client:
    auth = None
    user = (settings.opensearch_username or "").strip()
    password = settings.opensearch_password or ""
    if user:
        auth = (user, password)
    return httpx.Client(
        timeout=kwargs.pop("timeout", 5.0),
        auth=auth,
        verify=bool(settings.opensearch_verify_tls),
        **kwargs,
    )


def _index_name(kind: str) -> str:
    day = datetime.now(UTC).strftime("%Y.%m.%d")
    if kind == "finding":
        return f"{FINDINGS_INDEX}-{day}"
    return f"{INCIDENTS_INDEX}-{day}"


def index_document(kind: str, doc_id: str, body: dict[str, Any]) -> None:
    """Index a document. Never raises — failures are logged only."""
    if not settings.opensearch_indexing or settings.use_sqlite:
        return
    url = (settings.opensearch_url or "").rstrip("/")
    if not url:
        return
    index = _index_name(kind)
    payload = dict(body)
    payload.setdefault("@timestamp", datetime.now(UTC).isoformat())
    try:
        with _client(timeout=0.5) as client:
            resp = client.put(f"{url}/{index}/_doc/{doc_id}", json=payload)
            if resp.status_code >= 400:
                logger.warning(
                    "opensearch index failed kind=%s id=%s status=%s body=%s",
                    kind,
                    doc_id,
                    resp.status_code,
                    resp.text[:300],
                )
    except Exception as exc:  # noqa: BLE001
        logger.warning("opensearch index error kind=%s id=%s: %s", kind, doc_id, exc)


def search(
    *,
    tenant_id: str,
    query: str,
    indices: str | None = None,
    size: int = 50,
) -> dict[str, Any]:
    """Proxy a simple multi-match search scoped to tenant_id."""
    url = (settings.opensearch_url or "").rstrip("/")
    if not url:
        raise RuntimeError("OPENSEARCH_URL is not configured")
    target = indices or f"{FINDINGS_INDEX}-*,{INCIDENTS_INDEX}-*"
    q = (query or "").strip()
    must: list[dict[str, Any]] = [
        {
            "bool": {
                "should": [
                    {"term": {"tenant_id.keyword": tenant_id}},
                    {"term": {"tenant_id": tenant_id}},
                ],
                "minimum_should_match": 1,
            }
        }
    ]
    if q:
        must.append(
            {
                "multi_match": {
                    "query": q,
                    "fields": [
                        "title^3",
                        "summary^2",
                        "finding_type",
                        "severity",
                        "asset_id",
                        "finding_id",
                        "incident_id",
                        "*",
                    ],
                }
            }
        )
    body = {
        "size": max(1, min(size, 200)),
        "query": {"bool": {"must": must}},
        "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}],
    }
    with _client(timeout=5.0) as client:
        resp = client.post(f"{url}/{target}/_search", json=body)
        resp.raise_for_status()
        return resp.json()


def finding_doc_from_row(row: Any) -> dict[str, Any]:
    payload = dict(getattr(row, "payload", None) or {})
    return {
        "doc_type": "finding",
        "tenant_id": row.tenant_id,
        "finding_id": row.finding_id,
        "finding_type": row.finding_type,
        "asset_id": row.asset_id,
        "service_id": row.service_id,
        "model_name": row.model_name,
        "calibrated_score": row.calibrated_score,
        "severity": row.severity_hint,
        "window_start": row.window_start.isoformat() if row.window_start else None,
        "window_end": row.window_end.isoformat() if row.window_end else None,
        "title": payload.get("title") or f"{row.finding_type} on {row.asset_id}",
        "summary": payload.get("summary"),
        "mitre_techniques": payload.get("mitre_techniques") or [],
        "mitre_tactics": payload.get("mitre_tactics") or [],
    }


def incident_doc_from_row(row: Any) -> dict[str, Any]:
    context = dict(getattr(row, "context", None) or {})
    return {
        "doc_type": "incident",
        "tenant_id": row.tenant_id,
        "incident_id": row.incident_id,
        "title": row.title,
        "summary": row.summary,
        "status": row.status,
        "severity": row.severity,
        "risk_score": row.risk_score,
        "assets": list(row.assets or []),
        "services": list(row.services or []),
        "finding_ids": list(row.finding_ids or []),
        "first_seen": row.first_seen.isoformat() if row.first_seen else None,
        "last_seen": row.last_seen.isoformat() if row.last_seen else None,
        "mitre_techniques": list(getattr(row, "mitre_techniques", None) or []),
        "mitre_tactics": list(getattr(row, "mitre_tactics", None) or []),
        "context": context,
        "site_id": context.get("site_id") or getattr(row, "site_id", None),
        "threat_intel": context.get("threat_intel") or getattr(row, "threat_intel", None),
    }
