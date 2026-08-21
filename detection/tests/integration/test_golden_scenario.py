"""Golden path §20.1: four modality findings → one high/critical incident."""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CORR_ROOT = ROOT / "services" / "correlation-engine"
INTEGRATION = Path(__file__).resolve().parent

# Drop any previously imported shared packages from other services.
for key in list(sys.modules):
    if key == "app" or key.startswith("app.") or key == "correlation_engine" or key.startswith("correlation_engine."):
        del sys.modules[key]

sys.path.insert(0, str(CORR_ROOT))
sys.path.insert(0, str(INTEGRATION))

from correlation_engine.scoring import FindingView, build_incident_payload  # noqa: E402
from golden_correlation import GoldenFinding, correlate_findings  # noqa: E402


def test_golden_build_incident_payload_four_findings() -> None:
    now = datetime(2026, 7, 26, 12, 0, tzinfo=timezone.utc)
    findings = [
        FindingView(
            finding_id="finding-code-1",
            finding_type="code_risk",
            tenant_id="tenant-acme",
            asset_id="host-payments",
            service_id="payments-api",
            calibrated_score=0.88,
            model_name="code-model",
            contributors=[{"file": "src/auth/session.py", "start_line": 104}],
            context={"deployment_age_minutes": 12},
            window_start=now,
            window_end=now,
        ),
        FindingView(
            finding_id="finding-log-1",
            finding_type="log_anomaly",
            tenant_id="tenant-acme",
            asset_id="host-payments",
            service_id="payments-api",
            calibrated_score=0.94,
            model_name="log-model",
            contributors=[
                {"type": "unexpected_template", "template_id": "tpl-privilege-change"}
            ],
            context={"deployment_age_minutes": 12},
            window_start=now,
            window_end=now,
        ),
        FindingView(
            finding_id="finding-metrics-1",
            finding_type="metrics_anomaly",
            tenant_id="tenant-acme",
            asset_id="host-payments",
            service_id="payments-api",
            calibrated_score=0.87,
            model_name="metrics-model",
            contributors=[{"metric": "http.error_rate", "observed": 0.12, "expected": 0.01}],
            context={"deployment_age_minutes": 12},
            window_start=now,
            window_end=now,
        ),
        FindingView(
            finding_id="finding-network-1",
            finding_type="network_anomaly",
            tenant_id="tenant-acme",
            asset_id="host-payments",
            service_id="payments-api",
            calibrated_score=0.91,
            model_name="network-model",
            contributors=[{"type": "new_external_peer"}],
            context={"deployment_age_minutes": 12},
            window_start=now,
            window_end=now,
        ),
    ]

    incident = build_incident_payload(findings, medium=0.6, high=0.8, critical=0.93)
    assert incident["severity"] in {"high", "critical"}
    assert set(incident["finding_ids"]) == {
        "finding-code-1",
        "finding-log-1",
        "finding-metrics-1",
        "finding-network-1",
    }


def test_golden_multi_model_correlation_creates_one_incident() -> None:
    findings = [
        GoldenFinding(
            model_name="code-model",
            tenant_id="tenant-acme",
            service_id="payments-api",
            score=0.74,
            severity="medium",
            summary="Authentication behavior modified",
            event_time="2026-07-26T12:00:00Z",
        ),
        GoldenFinding(
            model_name="log-model",
            tenant_id="tenant-acme",
            service_id="payments-api",
            score=0.91,
            severity="high",
            summary="Unexpected privilege-related sequence",
            event_time="2026-07-26T12:05:00Z",
        ),
        GoldenFinding(
            model_name="metrics-model",
            tenant_id="tenant-acme",
            service_id="payments-api",
            score=0.88,
            severity="high",
            summary="Error rate spike",
            event_time="2026-07-26T12:06:00Z",
        ),
        GoldenFinding(
            model_name="network-model",
            tenant_id="tenant-acme",
            service_id="payments-api",
            score=0.86,
            severity="high",
            summary="First-seen external destination",
            event_time="2026-07-26T12:07:00Z",
        ),
    ]
    incident = correlate_findings(findings)
    assert incident is not None
    assert incident["severity"] in {"high", "critical"}
    assert set(incident["evidence_models"]) == {
        "code-model",
        "log-model",
        "metrics-model",
        "network-model",
    }
    assert incident["feedback_retained"] is True
    assert incident["immediate_retrain"] is False


def test_incomplete_modality_set_does_not_open_incident() -> None:
    findings = [
        GoldenFinding(
            model_name="log-model",
            tenant_id="tenant-acme",
            service_id="payments-api",
            score=0.99,
            severity="critical",
            summary="alone",
        )
    ]
    assert correlate_findings(findings) is None
