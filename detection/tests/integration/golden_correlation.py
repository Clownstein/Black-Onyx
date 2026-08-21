"""Lightweight golden-path correlator used by integration tests."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class GoldenFinding:
    model_name: str
    tenant_id: str
    service_id: str
    score: float
    severity: str
    summary: str
    evidence: dict[str, Any] = field(default_factory=dict)
    event_time: str = "2026-07-26T12:00:00Z"


def correlate_findings(findings: list[GoldenFinding]) -> dict[str, Any] | None:
    """Require all four modality models before opening a golden incident."""
    models = {f.model_name for f in findings}
    required = {"code-model", "log-model", "metrics-model", "network-model"}
    if not required.issubset(models):
        return None
    max_score = max(f.score for f in findings)
    severity = "critical" if max_score >= 0.93 else "high"
    timeline = sorted(
        [
            {
                "event_time": f.event_time,
                "model_name": f.model_name,
                "summary": f.summary,
                "score": f.score,
            }
            for f in findings
        ],
        key=lambda item: item["event_time"],
    )
    return {
        "incident_id": "inc-golden-01",
        "tenant_id": findings[0].tenant_id,
        "service_id": findings[0].service_id,
        "severity": severity,
        "risk_score": max_score,
        "evidence_models": sorted(models),
        "timeline": timeline,
        "feedback_retained": True,
        "immediate_retrain": False,
    }
