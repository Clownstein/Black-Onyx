from __future__ import annotations

from datetime import datetime, timedelta, timezone

from correlation_engine.engine import CorrelationEngine
from correlation_engine.scoring import FindingView, build_incident_payload


def test_build_incident_copies_site_id_from_finding_context() -> None:
    end = datetime.now(timezone.utc)
    findings = [
        FindingView(
            finding_id="f1",
            finding_type="network_anomaly",
            tenant_id="t1",
            asset_id="a1",
            service_id="svc",
            calibrated_score=0.8,
            model_name="network-model",
            contributors=[],
            context={"site_id": "plant-a"},
            window_start=end - timedelta(minutes=5),
            window_end=end,
        )
    ]
    incident = build_incident_payload(
        findings, medium=0.4, high=0.7, critical=0.9, asset_criticality=0.5
    )
    assert incident["context"]["site_id"] == "plant-a"


def test_engine_promotes_top_level_site_id() -> None:
    engine = CorrelationEngine()
    now = datetime.now(timezone.utc)
    incident = engine.ingest_finding(
        {
            "finding_id": "f-site-1",
            "finding_type": "log_anomaly",
            "tenant_id": "tenant-a",
            "asset_id": "host-1",
            "service_id": "api",
            "calibrated_score": 0.7,
            "model_name": "log-model",
            "site_id": "dc-east",
            "window": {
                "start": (now - timedelta(minutes=5)).isoformat(),
                "end": now.isoformat(),
            },
        }
    )
    assert incident is not None
    assert incident["context"]["site_id"] == "dc-east"
