"""Correlation windows and incident emission (memory or Redis-backed)."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

import httpx
from black_onyx_contracts.incident import Incident

from correlation_engine.config import settings
from correlation_engine.kill_chains import apply_kill_chain_boost
from correlation_engine.scoring import FindingView, build_incident_payload, refresh_incident_narrative
from correlation_engine.store import BucketState, BucketStore, build_bucket_store
from correlation_engine.threat_intel import enrich_incident_with_threat_intel

logger = logging.getLogger("correlation-engine")


def _parse_dt(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


class CorrelationEngine:
    def __init__(self, store: BucketStore | None = None) -> None:
        self._store = store or build_bucket_store()

    def _key(self, tenant_id: str, asset_id: str, service_id: str | None) -> str:
        return f"{tenant_id}|{asset_id}|{service_id or '-'}"

    async def persist_finding(self, finding: dict[str, Any]) -> None:
        """Idempotently store every canonical finding before correlation/ack."""
        tenant_id = str(finding.get("tenant_id") or "").strip()
        if not tenant_id:
            raise ValueError("finding.tenant_id is required")
        if not settings.incident_api_service_key:
            raise RuntimeError("incident-api service key is not configured")
        url = settings.incident_api_url.rstrip("/") + "/api/v1/findings"
        body = {
            key: finding.get(key)
            for key in (
                "finding_id", "finding_type", "title", "summary", "asset_id", "service_id",
                "model_name", "model_version", "feature_version", "raw_score", "calibrated_score",
                "severity_hint", "window", "contributors", "evidence_refs", "context",
                "fingerprint", "category", "schema_version",
            )
            if key in finding
        }
        headers = {
            "X-Tenant-Id": tenant_id,
            "X-Service-Key": settings.incident_api_service_key,
        }
        async with httpx.AsyncClient(
            timeout=10.0, trust_env=False, follow_redirects=False,
        ) as client:
            response = await client.post(url, json=body, headers=headers)
            response.raise_for_status()

    def _build_incident(
        self, bucket: BucketState, tenant_id: str, asset_criticality: float | None = None,
    ) -> dict[str, Any]:
        incident = build_incident_payload(
            bucket.findings,
            medium=settings.severity_medium,
            high=settings.severity_high,
            critical=settings.severity_critical,
            asset_criticality=(
                settings.asset_criticality_default if asset_criticality is None else asset_criticality
            ),
        )
        incident["tenant_id"] = tenant_id
        incident["_correlation_key"] = self._key(bucket.tenant_id, bucket.asset_id, bucket.service_id)
        if bucket.incident_id:
            incident["incident_id"] = bucket.incident_id
        else:
            bucket.incident_id = f"inc-{uuid4().hex[:12]}"
            incident["incident_id"] = bucket.incident_id
        apply_kill_chain_boost(incident, bucket.findings)
        enrich_incident_with_threat_intel(incident, bucket.findings)
        refresh_incident_narrative(incident, bucket.findings)
        return incident

    def ingest_finding(
        self, payload: dict[str, Any], *, asset_criticality: float | None = None,
    ) -> dict[str, Any] | None:
        required = ("finding_id", "finding_type", "tenant_id", "asset_id", "model_name")
        missing = [name for name in required if not str(payload.get(name) or "").strip()]
        if missing:
            raise ValueError(f"finding is missing required fields: {', '.join(missing)}")
        window = payload.get("window") or {}
        if not isinstance(window, dict) or not window.get("start") or not window.get("end"):
            raise ValueError("finding.window.start and finding.window.end are required")
        ctx = dict(payload.get("context") or {})
        # Promote envelope / finding-level site_id into context for incident provenance.
        if payload.get("site_id") and "site_id" not in ctx:
            ctx["site_id"] = payload["site_id"]
        title = payload.get("title")
        if isinstance(title, str) and title.strip() and "title" not in ctx:
            ctx["title"] = title.strip()
        summary = payload.get("summary")
        if isinstance(summary, str) and summary.strip() and "summary" not in ctx:
            ctx["summary"] = summary.strip()
        finding = FindingView(
            finding_id=str(payload["finding_id"]),
            finding_type=str(payload["finding_type"]),
            tenant_id=str(payload["tenant_id"]),
            asset_id=str(payload["asset_id"]),
            service_id=payload.get("service_id"),
            calibrated_score=float(payload.get("calibrated_score") or 0.0),
            model_name=str(payload["model_name"]),
            contributors=list(payload.get("contributors") or []),
            evidence_refs=list(payload.get("evidence_refs") or []),
            context=ctx,
            window_start=_parse_dt(window.get("start")),
            window_end=_parse_dt(window.get("end")),
        )
        key = self._key(finding.tenant_id, finding.asset_id, finding.service_id)
        now = datetime.now(timezone.utc)
        bucket = self._store.get(key)
        if bucket is None or (now - bucket.last_updated) > timedelta(
            minutes=settings.initial_window_minutes
        ):
            bucket = BucketState(
                tenant_id=finding.tenant_id,
                asset_id=finding.asset_id,
                service_id=finding.service_id,
            )

        already = any(f.finding_id == finding.finding_id for f in bucket.findings)
        if already:
            if bucket.last_publish_ok:
                return None
            incident = self._build_incident(bucket, finding.tenant_id, asset_criticality)
            self._store.put(key, bucket)
            return incident

        bucket.findings.append(finding)
        bucket.last_updated = now
        bucket.last_publish_ok = False
        incident = self._build_incident(bucket, finding.tenant_id, asset_criticality)
        self._store.put(key, bucket)
        return incident

    def mark_publish_ok(self, incident: dict[str, Any]) -> None:
        key = str(incident.get("_correlation_key") or "")
        if not key:
            return
        bucket = self._store.get(key)
        if bucket is not None and bucket.incident_id == incident.get("incident_id"):
            bucket.last_publish_ok = True
            self._store.put(key, bucket)

    def mark_publish_failed(self, incident: dict[str, Any]) -> None:
        key = str(incident.get("_correlation_key") or "")
        if not key:
            return
        bucket = self._store.get(key)
        if bucket is not None and bucket.incident_id == incident.get("incident_id"):
            bucket.last_publish_ok = False
            self._store.put(key, bucket)

    async def publish_incident(self, incident: dict[str, Any]) -> None:
        """Persist via incident-api internal create (tenant-isolated)."""
        url = settings.incident_api_url.rstrip("/") + "/api/v1/incidents"
        headers = {"X-Tenant-Id": str(incident["tenant_id"])}
        if settings.incident_api_service_key:
            headers["X-Service-Key"] = settings.incident_api_service_key
        payload = {
            "incident_id": incident.get("incident_id"),
            "title": incident["title"],
            "status": incident.get("status", "open"),
            "severity": incident["severity"],
            "risk_score": incident["risk_score"],
            "category": incident.get("category") or [],
            "first_seen": incident["first_seen"],
            "last_seen": incident["last_seen"],
            "assets": incident.get("assets") or [],
            "services": incident.get("services") or [],
            "finding_ids": incident.get("finding_ids") or [],
            "summary": incident.get("summary") or "",
            "opening_reason": incident.get("opening_reason")
            or (incident.get("context") or {}).get("opening_reason"),
            "models": incident.get("models") or [],
            "deployment_id": incident.get("deployment_id"),
            "commit": incident.get("commit"),
            "evidence": incident.get("evidence") or [],
            "context": incident.get("context") or {},
        }
        try:
            async with httpx.AsyncClient(
                timeout=10.0, trust_env=False, follow_redirects=False
            ) as client:
                resp = await client.post(url, json=payload, headers=headers)
                resp.raise_for_status()
        except Exception:
            self.mark_publish_failed(incident)
            raise

        self.mark_publish_ok(incident)

        if not incident.get("suppress_notification"):
            await self._notify_incident(incident)

    async def _notify_incident(self, incident: dict[str, Any]) -> None:
        """Best-effort notify; soft-fail so correlation is not blocked."""
        url = settings.notification_url
        tenant_id = str(incident["tenant_id"])
        headers: dict[str, str] = {"X-Tenant-Id": tenant_id}
        if settings.incident_api_service_key:
            headers["X-Service-Key"] = settings.incident_api_service_key
        if settings.notification_api_key:
            headers["X-API-Key"] = settings.notification_api_key
        try:
            async with httpx.AsyncClient(
                timeout=10.0, trust_env=False, follow_redirects=False
            ) as client:
                policy_url = settings.incident_api_url.rstrip("/") + "/api/v1/settings/notifications/internal"
                policy_response = await client.get(policy_url, headers=headers)
                policy_response.raise_for_status()
                notification_policy = policy_response.json()
                if not isinstance(notification_policy, list):
                    raise ValueError("notification policy response is invalid")
            notification = Incident.model_validate(
                {key: incident[key] for key in Incident.model_fields if key in incident}
            ).model_dump(mode="json")
            if incident.get("notify_email"):
                notification["notify_email"] = incident["notify_email"]
            notification["notification_policy"] = notification_policy
            async with httpx.AsyncClient(
                timeout=10.0, trust_env=False, follow_redirects=False
            ) as client:
                resp = await client.post(url, json=notification, headers=headers)
                resp.raise_for_status()
        except Exception:
            logger.exception("notification soft-fail for incident %s", incident.get("incident_id"))
