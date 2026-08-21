"""In-process golden-path helpers for §20.1 integration tests."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4


@dataclass(frozen=True)
class GoldenFinding:
    model_name: str
    tenant_id: str
    service_id: str
    score: float
    severity: str
    summary: str
    evidence: dict[str, Any] = field(default_factory=dict)
    event_time: str | None = None


_SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def _max_severity(findings: list[GoldenFinding]) -> str:
    return max((f.severity for f in findings), key=lambda s: _SEVERITY_RANK.get(s, 0))


def correlate_findings(findings: list[GoldenFinding]) -> dict[str, Any] | None:
    """
    Create one incident when log/code/network/metrics findings co-occur
    for the same tenant+service with elevated severity.
    """
    if not findings:
        return None

    tenant_id = findings[0].tenant_id
    service_id = findings[0].service_id
    if any(f.tenant_id != tenant_id or f.service_id != service_id for f in findings):
        return None

    by_model = {f.model_name for f in findings}
    required = {"log-model", "code-model", "network-model", "metrics-model"}
    if not required.issubset(by_model):
        return None

    severity = _max_severity(findings)
    if _SEVERITY_RANK.get(severity, 0) < _SEVERITY_RANK["high"]:
        return None

    timeline = sorted(
        [
            {
                "event_time": f.event_time or datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                "model_name": f.model_name,
                "summary": f.summary,
                "score": f.score,
                "severity": f.severity,
                "evidence": f.evidence,
            }
            for f in findings
        ],
        key=lambda item: item["event_time"],
    )
    return {
        "incident_id": f"inc-{uuid4().hex[:12]}",
        "tenant_id": tenant_id,
        "service_id": service_id,
        "severity": severity,
        "status": "open",
        "title": f"Correlated anomaly on {service_id}",
        "summary": "Multi-model correlation across code, logs, metrics, and network",
        "timeline": timeline,
        "evidence_models": sorted(by_model),
        "feedback_retained": True,
        "immediate_retrain": False,
    }
