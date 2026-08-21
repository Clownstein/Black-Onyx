"""HTTP client for posting enrichment results to incident-api."""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import httpx

from code_enrichment_worker.config import settings

logger = logging.getLogger(__name__)


def post_enrichment_finding(
    *,
    tenant_id: str,
    finding_id: str | None,
    asset_id: str,
    service_id: str | None,
    evidence_refs: list[str],
    contributors: list[dict[str, Any]],
    cwe_ids: list[str],
    enrichment: dict[str, Any],
    calibrated_score: float = 0.5,
    severity_hint: str | None = "medium",
) -> dict[str, Any]:
    """Upsert a findings row (or enrichment overlay) via incident-api service key.

    Human review is always required; this never requests autonomous remediation.
    """
    fid = finding_id or f"finding-enrich-{uuid4().hex[:12]}"
    now = datetime.now(UTC)
    window_start = now - timedelta(minutes=5)
    window_end = now + timedelta(minutes=5)

    context = {
        "code_enrichment": enrichment,
        "cwe_ids": cwe_ids,
        "human_review_required": True,
        "autonomous_remediation": False,
        "title": "Antares code enrichment (advisory)",
        "summary": (
            "File-level CWE localization leads from Antares CLI. "
            "Requires human review; not proof of vulnerability."
        ),
    }
    body: dict[str, Any] = {
        "finding_id": fid,
        "finding_type": "code_enrichment",
        "asset_id": asset_id or "repo",
        "service_id": service_id,
        "model_name": "antares-enrichment",
        "model_version": "0.1.0",
        "raw_score": calibrated_score,
        "calibrated_score": max(0.0, min(1.0, calibrated_score)),
        "severity_hint": severity_hint,
        "window": {
            "start": window_start.isoformat().replace("+00:00", "Z"),
            "end": window_end.isoformat().replace("+00:00", "Z"),
        },
        "contributors": contributors,
        "evidence_refs": evidence_refs,
        "context": context,
        "schema_version": "1.0",
    }

    url = f"{settings.incident_api_url.rstrip('/')}/api/v1/findings"
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "X-Tenant-Id": tenant_id or "default",
    }
    if settings.incident_api_service_key:
        headers["X-Service-Key"] = settings.incident_api_service_key

    try:
        with httpx.Client(timeout=settings.incident_api_timeout_seconds) as client:
            resp = client.post(url, json=body, headers=headers)
            if resp.status_code >= 400:
                logger.warning(
                    "incident-api enrich post failed status=%s body=%s",
                    resp.status_code,
                    resp.text[:500],
                )
                return {
                    "ok": False,
                    "status_code": resp.status_code,
                    "error": resp.text[:500],
                    "finding_id": fid,
                }
            return {"ok": True, "status_code": resp.status_code, "finding_id": fid, "body": resp.json()}
    except httpx.HTTPError as exc:
        logger.warning("incident-api enrich post error: %s", exc)
        return {"ok": False, "error": str(exc), "finding_id": fid}


def fetch_high_risk_code_findings(
    *,
    tenant_id: str,
    min_score: float,
) -> list[dict[str, Any]]:
    """Poll incident-api for high-risk code findings (best-effort)."""
    url = f"{settings.incident_api_url.rstrip('/')}/api/v1/findings"
    headers = {
        "Accept": "application/json",
        "X-Tenant-Id": tenant_id or "default",
    }
    if settings.incident_api_service_key:
        headers["X-Service-Key"] = settings.incident_api_service_key
    params = {"min_score": min_score, "type": "code_risk"}
    try:
        with httpx.Client(timeout=settings.incident_api_timeout_seconds) as client:
            resp = client.get(url, headers=headers, params=params)
            if resp.status_code >= 400:
                return []
            payload = resp.json()
            items = payload.get("items") if isinstance(payload, dict) else payload
            return [i for i in (items or []) if isinstance(i, dict)]
    except httpx.HTTPError:
        return []
