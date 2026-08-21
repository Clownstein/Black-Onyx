"""Incident risk scoring and deterministic rules."""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


def sigmoid(x: float) -> float:
    if x >= 0:
        z = math.exp(-x)
        return 1.0 / (1.0 + z)
    z = math.exp(x)
    return z / (1.0 + z)


@dataclass
class FindingView:
    finding_id: str
    finding_type: str
    tenant_id: str
    asset_id: str
    service_id: str | None
    calibrated_score: float
    model_name: str
    contributors: list[dict[str, Any]] = field(default_factory=list)
    context: dict[str, Any] = field(default_factory=dict)
    window_start: datetime | None = None
    window_end: datetime | None = None


def feature_vector(findings: list[FindingView], asset_criticality: float = 0.5) -> dict[str, Any]:
    by_type = {
        "log": 0.0,
        "code": 0.0,
        "network": 0.0,
        "metrics": 0.0,
        "host_state": 0.0,
        "firewall": 0.0,
        "malware": 0.0,
    }
    for f in findings:
        key = "log"
        ft = f.finding_type.lower()
        if "malware" in ft:
            key = "malware"
        elif "code" in ft:
            key = "code"
        elif "firewall" in ft:
            key = "firewall"
        elif "host_state" in ft or "host-state" in ft:
            key = "host_state"
        elif "suricata" in ft or "network" in ft or "flow" in ft:
            key = "network"
        elif "metric" in ft:
            key = "metrics"
        by_type[key] = max(by_type[key], f.calibrated_score)

    models = {f.model_name for f in findings}
    new_external = any(
        any(c.get("type") == "new_external_peer" for c in f.contributors) for f in findings
    )
    auth_related = any(
        any(
            "auth" in str(c.get("template_id", "")).lower()
            or "privilege" in str(c.get("type", "")).lower()
            or "privilege" in str(c.get("template_id", "")).lower()
            for c in f.contributors
        )
        for f in findings
    )
    error_rate = any(
        any(c.get("metric") == "http.error_rate" for c in f.contributors) for f in findings
    )
    deployment_age = None
    for f in findings:
        if "deployment_age_minutes" in f.context:
            deployment_age = float(f.context["deployment_age_minutes"])
            break

    log_category = None
    for f in findings:
        for c in f.contributors:
            tid = str(c.get("template_id") or "")
            if "privilege" in tid.lower():
                log_category = "privilege_change"
        if f.context.get("log_category"):
            log_category = str(f.context["log_category"])

    return {
        "max_log_score": by_type["log"],
        "max_code_score": by_type["code"],
        "max_network_score": by_type["network"],
        "max_metrics_score": by_type["metrics"],
        "max_host_state_score": by_type["host_state"],
        "max_firewall_score": by_type["firewall"],
        "max_malware_score": by_type["malware"],
        "model_count": len(models),
        "finding_count": len(findings),
        "asset_criticality": asset_criticality,
        "deployment_age_minutes": deployment_age if deployment_age is not None else 9999.0,
        "new_external_peer": new_external,
        "network_new_external_peer": new_external
        or any(f.context.get("new_external_peer") for f in findings),
        "auth_related_log": auth_related,
        "log_category": log_category,
        "code_category": next(
            (f.context.get("code_category") for f in findings if f.context.get("code_category")),
            None,
        ),
        "deployment_commit_matches": any(
            f.context.get("deployment_commit_matches") for f in findings
        ),
        "error_rate_anomaly": error_rate,
        "known_maintenance": any(f.context.get("known_maintenance") for f in findings),
        "deterministic_security_indicator": any(
            f.context.get("deterministic_security_indicator") for f in findings
        ),
        "join_keys": sorted(
            {
                f"{k}:{v}"
                for f in findings
                for k, v in (
                    ("community_id", f.context.get("community_id")),
                    ("zeek_uid", f.context.get("zeek_uid")),
                    ("asset_id", f.asset_id or f.context.get("asset_id")),
                )
                if v
            }
        ),
    }


def incident_risk(features: dict[str, Any]) -> float:
    """Logistic risk.

    Phase 1 baseline (platform §10.6 / task brief):
      sigmoid(b0 + b1 * max_log_score + b5 * asset_criticality)

    Additional modality terms remain for multi-signal correlation.
    """
    from correlation_engine.config import settings

    b0 = settings.b0
    b1 = settings.b1
    b5 = settings.b5
    x = (
        b0
        + b1 * float(features["max_log_score"])
        + 1.4 * float(features["max_code_score"])
        + 1.6 * float(features["max_network_score"])
        + 1.5 * float(features["max_metrics_score"])
        + 1.55 * float(features.get("max_host_state_score") or 0.0)
        + 1.45 * float(features.get("max_firewall_score") or 0.0)
        + 1.7 * float(features.get("max_malware_score") or 0.0)
        + b5 * float(features["asset_criticality"])
        + 0.35 * float(features["model_count"])
        + (0.6 if float(features["deployment_age_minutes"]) <= 30 else 0.0)
        + (0.7 if features["new_external_peer"] else 0.0)
        - (1.5 if features["known_maintenance"] else 0.0)
        + 0.35 * float(features.get("vector_novelty") or 0.0)
    )
    return float(sigmoid(x))


def severity_from_score(score: float, medium: float, high: float, critical: float) -> str:
    if score >= critical:
        return "critical"
    if score >= high:
        return "high"
    if score >= medium:
        return "medium"
    return "low"


def apply_deterministic_rules(features: dict[str, Any], severity: str) -> tuple[str, list[str]]:
    """Return (severity, categories) after rules."""
    categories: list[str] = []
    order = ["low", "medium", "high", "critical"]

    def bump(min_sev: str) -> None:
        nonlocal severity
        if order.index(min_sev) > order.index(severity):
            severity = min_sev

    # A.6: new-peer-after-privilege-change
    if (
        float(features["max_network_score"]) >= 0.85
        and features["new_external_peer"]
        and (features["auth_related_log"] or features.get("log_category") == "privilege_change")
    ):
        bump("high")
        categories.append("suspicious_egress")
        categories.append("authentication_change")

    if (
        float(features["max_metrics_score"]) >= 0.80
        and float(features["deployment_age_minutes"]) <= 30
        and features["error_rate_anomaly"]
    ):
        categories.append("deployment_regression")

    # A.6: deployed-risky-egress
    if (
        float(features["max_code_score"]) >= 0.85
        and (
            features.get("code_category") == "network_egress"
            or features["new_external_peer"]
        )
        and features.get("network_new_external_peer", features["new_external_peer"])
        and (
            features.get("deployment_commit_matches")
            or float(features["deployment_age_minutes"]) <= 30
        )
    ):
        bump("critical")
        categories.append("suspicious_egress")

    if features["known_maintenance"] and not features.get("deterministic_security_indicator"):
        categories.append("maintenance")

    if features["auth_related_log"]:
        categories.append("authentication_change")

    return severity, categories


def build_incident_payload(
    findings: list[FindingView],
    *,
    medium: float,
    high: float,
    critical: float,
    asset_criticality: float = 0.9,
) -> dict[str, Any]:
    features = feature_vector(findings, asset_criticality=asset_criticality)
    novelty = _optional_vector_novelty(findings)
    if novelty is not None:
        features["vector_novelty"] = novelty
    risk = incident_risk(features)
    severity = severity_from_score(risk, medium, high, critical)
    severity, categories = apply_deterministic_rules(features, severity)

    assets = sorted({f.asset_id for f in findings})
    services = sorted({f.service_id for f in findings if f.service_id})
    models = sorted({f.model_name for f in findings})
    now = datetime.now(timezone.utc)
    starts = [f.window_start for f in findings if f.window_start]
    ends = [f.window_end for f in findings if f.window_end]
    first_seen = min(starts) if starts else now
    last_seen = max(ends) if ends else now

    title_bits = []
    if features["new_external_peer"]:
        title_bits.append("new external peer")
    if features["auth_related_log"]:
        title_bits.append("authentication anomaly")
    if features["error_rate_anomaly"]:
        title_bits.append("elevated errors")
    title = (
        f"{services[0] if services else assets[0]}: " + ", ".join(title_bits)
        if title_bits
        else f"Correlated anomaly on {assets[0]}"
    )

    suppress_notification = bool(
        features["known_maintenance"] and "suspicious_egress" not in categories
    )

    deployment_id = None
    commit = None
    site_id = None
    for f in findings:
        if deployment_id is None and f.context.get("deployment_id"):
            deployment_id = str(f.context["deployment_id"])
        if commit is None and f.context.get("commit"):
            commit = str(f.context["commit"])
        if site_id is None and f.context.get("site_id"):
            site_id = str(f.context["site_id"])

    evidence: list[dict[str, Any]] = []
    for f in findings:
        kind = "correlation"
        ft = f.finding_type.lower()
        if "log" in ft:
            kind = "logs"
        elif "firewall" in ft:
            kind = "firewall"
        elif "host_state" in ft or "host-state" in ft:
            kind = "host_state"
        elif "net" in ft or "flow" in ft or "suricata" in ft:
            kind = "network"
        elif "malware" in ft:
            kind = "malware"
        elif "metric" in ft:
            kind = "metrics"
        elif "code" in ft:
            kind = "code"
        evidence.append(
            {
                "kind": kind,
                "model": f.model_name,
                "title": f"{f.finding_type} on {f.asset_id}",
                "detail": f"calibrated_score={f.calibrated_score:.3f}",
                "score": f.calibrated_score,
                "timestamp": (f.window_end or now).isoformat(),
                "raw": {
                    "finding_id": f.finding_id,
                    "finding_type": f.finding_type,
                    "contributors": f.contributors,
                    "context": f.context,
                },
            }
        )

    related_finding_ids = _optional_related_finding_ids(findings)
    context: dict[str, Any] = {
        "features": {
            k: features[k]
            for k in (
                "max_log_score",
                "max_code_score",
                "max_network_score",
                "max_metrics_score",
                "max_host_state_score",
                "max_firewall_score",
                "max_malware_score",
                "model_count",
            )
        },
        "deployment_id": deployment_id,
        "commit": commit,
        "join_keys": features.get("join_keys") or [],
        **({"site_id": site_id} if site_id else {}),
    }
    if related_finding_ids:
        context["related_finding_ids"] = related_finding_ids

    return {
        "title": title,
        "status": "suppressed" if suppress_notification else "open",
        "severity": severity,
        "risk_score": round(risk, 4),
        "category": categories or ["anomaly"],
        "first_seen": first_seen.isoformat(),
        "last_seen": last_seen.isoformat(),
        "assets": assets,
        "services": services,
        "finding_ids": [f.finding_id for f in findings],
        "models": models,
        "deployment_id": deployment_id,
        "commit": commit,
        "evidence": evidence,
        "context": context,
        "summary": (
            f"{len(findings)} findings from {len(models)} models; "
            f"risk={risk:.2f}; features={ {k: features[k] for k in ('max_log_score','max_code_score','max_network_score','max_metrics_score','max_host_state_score','max_firewall_score','max_malware_score','model_count')} }"
        ),
        "features": features,
        "suppress_notification": suppress_notification,
    }


def _optional_vector_novelty(findings: list[FindingView]) -> float | None:
    """Return novelty score when VECTOR_NOVELTY_ENABLED; else None (no score change)."""
    try:
        from correlation_engine.config import settings
    except Exception:
        return None
    if not settings.vector_novelty_enabled:
        return None
    values: list[float] = []
    for f in findings:
        for c in f.contributors:
            if c.get("name") == "vector_novelty" and c.get("enabled"):
                try:
                    values.append(float(c.get("value") or 0.0))
                except (TypeError, ValueError):
                    continue
    if values:
        return max(0.0, min(1.0, max(values)))
    # No contributor means the capability is unavailable; do not fabricate
    # novelty that would change the incident score.
    return None


def _optional_related_finding_ids(findings: list[FindingView]) -> list[str]:
    """Best-effort Qdrant neighbors; never changes risk score; no-op when disabled."""
    try:
        from correlation_engine.config import settings
    except Exception:
        return []
    if not settings.vector_search_enabled or not (settings.qdrant_url or "").strip():
        return []
    if not findings:
        return []
    try:
        import httpx

        from black_onyx_vector import VectorClient

        seed = findings[0]
        text = f"{seed.finding_type} {seed.asset_id} {seed.calibrated_score}"
        embed_base = (settings.embedding_service_url or "").strip()
        if not embed_base:
            return []
        with httpx.Client(timeout=10.0) as http:
            response = http.post(
                f"{embed_base.rstrip('/')}/api/v1/embed/text",
                json={"text": text},
            )
            response.raise_for_status()
            vector = response.json().get("vector")
        if not isinstance(vector, list) or not vector:
            return []
        dense = [float(value) for value in vector]
        client = VectorClient(url=settings.qdrant_url)
        if not client.available:
            return []
        hits = client.search(
            "findings_v1",
            dense,
            seed.tenant_id,
            limit=5,
        )
        known = {f.finding_id for f in findings}
        out: list[str] = []
        for h in hits:
            fid = (h.get("payload") or {}).get("finding_id")
            if fid and fid not in known and fid not in out:
                out.append(str(fid))
        return out
    except Exception as exc:  # noqa: BLE001 - optional capability must not break scoring
        logger.warning("related-finding vector lookup unavailable: %s", exc)
        return []
