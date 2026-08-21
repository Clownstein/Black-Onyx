"""Best-effort persist of vulnerability findings to incident-api."""

from __future__ import annotations

import logging
from typing import Any

import httpx

from integration_hub.config import settings

logger = logging.getLogger("integration-hub.findings_persist")


async def persist_findings(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """POST each finding to incident-api. Soft-fails; never raises to the caller."""
    if not settings.persist_findings:
        return {"enabled": False, "persisted": 0, "failed": 0}
    base = (settings.incident_api_url or "").strip()
    if not base or not findings:
        return {"enabled": bool(base), "persisted": 0, "failed": 0}

    url = base.rstrip("/") + "/api/v1/findings"
    persisted = 0
    failed = 0
    async with httpx.AsyncClient(timeout=settings.incident_api_timeout_seconds) as client:
        for finding in findings:
            tenant_id = str(finding.get("tenant_id") or "default")
            window = finding.get("window") or {}
            body = {
                "finding_id": finding.get("finding_id"),
                "finding_type": finding.get("finding_type") or "vulnerability",
                "asset_id": finding.get("asset_id") or "unknown",
                "service_id": finding.get("service_id"),
                "model_name": finding.get("model_name") or "vuln-ingest",
                "model_version": finding.get("model_version"),
                "feature_version": finding.get("feature_version"),
                "raw_score": float(finding.get("raw_score") or 0.0),
                "calibrated_score": float(finding.get("calibrated_score") or 0.0),
                "severity_hint": finding.get("severity_hint"),
                "window": {
                    "start": window.get("start"),
                    "end": window.get("end"),
                },
                "contributors": list(finding.get("contributors") or []),
                "evidence_refs": list(finding.get("evidence_refs") or []),
                "context": dict(finding.get("context") or {}),
                "fingerprint": finding.get("fingerprint"),
                "category": list(finding.get("category") or []),
                "schema_version": str(finding.get("schema_version") or "1.0"),
                "mitre_techniques": list(finding.get("mitre_techniques") or []),
                "mitre_tactics": list(finding.get("mitre_tactics") or []),
            }
            if body["window"]["start"] is None or body["window"]["end"] is None:
                failed += 1
                continue
            headers = {"X-Tenant-Id": tenant_id}
            key = (settings.incident_api_service_key or "").strip()
            if key:
                headers["X-Service-Key"] = key
            try:
                resp = await client.post(url, json=body, headers=headers)
                resp.raise_for_status()
                persisted += 1
            except Exception:
                logger.exception(
                    "failed to persist vuln finding %s",
                    finding.get("finding_id"),
                )
                failed += 1
    return {"enabled": True, "persisted": persisted, "failed": failed}
