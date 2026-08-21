"""In-process four-model findings → correlated incident → incident-api persist."""

from __future__ import annotations

import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

ROOT = Path(__file__).resolve().parents[2]


def _finding(
    *,
    finding_id: str,
    finding_type: str,
    model_name: str,
    score: float,
    contributors: list[dict],
    context: dict | None = None,
) -> dict:
    now = datetime.now(UTC)
    start = (now - timedelta(minutes=5)).isoformat()
    end = (now + timedelta(minutes=5)).isoformat()
    return {
        "finding_id": finding_id,
        "finding_type": finding_type,
        "tenant_id": "tenant-demo",
        "asset_id": "host-1",
        "service_id": "payments-api",
        "model_name": model_name,
        "model_version": "0.1.0",
        "raw_score": score,
        "calibrated_score": score,
        "severity_hint": "high",
        "window": {"start": start, "end": end},
        "contributors": contributors,
        "evidence_refs": [],
        "context": {
            "deployment_id": "deploy-1",
            "commit": "abc123",
            "deployment_age_minutes": 10,
            **(context or {}),
        },
        "fingerprint": finding_id,
        "category": [],
    }


def test_features_to_findings_to_correlated_incident():
    # Import correlation-engine package.
    corr_path = str(ROOT / "services" / "correlation-engine")
    sys.path.insert(0, corr_path)
    from correlation_engine.engine import CorrelationEngine
    from correlation_engine.store import MemoryBucketStore

    finding_payloads = [
        _finding(
            finding_id="fnd-log",
            finding_type="log_anomaly",
            model_name="log-model",
            score=0.92,
            contributors=[
                {"type": "template", "contribution": 0.9, "template_id": "auth.privilege"},
            ],
            context={"log_category": "privilege_change"},
        ),
        _finding(
            finding_id="fnd-net",
            finding_type="network_anomaly",
            model_name="network-model",
            score=0.91,
            contributors=[
                {"type": "new_external_peer", "contribution": 0.95, "summary": "1.2.3.4"},
            ],
            context={"new_external_peer": True},
        ),
        _finding(
            finding_id="fnd-met",
            finding_type="metrics_anomaly",
            model_name="metrics-model",
            score=0.88,
            contributors=[
                {"type": "metric", "contribution": 0.88, "metric": "http.error_rate"},
            ],
        ),
        _finding(
            finding_id="fnd-code",
            finding_type="code_risk",
            model_name="code-model",
            score=0.87,
            contributors=[{"type": "scanner", "contribution": 0.9, "summary": "egress"}],
            context={"code_category": "network_egress", "deployment_commit_matches": True},
        ),
    ]

    engine = CorrelationEngine(store=MemoryBucketStore())
    incident = None
    for fp in finding_payloads:
        incident = engine.ingest_finding(fp)
        assert incident is not None

    assert incident is not None
    assert len(incident["finding_ids"]) == 4
    assert set(incident["models"]) >= {"log-model", "network-model", "metrics-model", "code-model"}
    assert len(incident["evidence"]) == 4
    assert incident.get("deployment_id") == "deploy-1"

    # Drop correlation modules so incident-api packages load cleanly.
    for key in list(sys.modules):
        if (
            key == "app"
            or key.startswith("app.")
            or key == "correlation_engine"
            or key.startswith("correlation_engine.")
        ):
            del sys.modules[key]
    if corr_path in sys.path:
        sys.path.remove(corr_path)

    sys.path.insert(0, str(ROOT / "services" / "incident-api"))
    from incident_api.db import Base, get_db
    from incident_api.main import app as incident_app

    db_engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Session = sessionmaker(bind=db_engine)
    Base.metadata.create_all(bind=db_engine)

    def override():
        db = Session()
        try:
            yield db
        finally:
            db.close()

    incident_app.dependency_overrides[get_db] = override
    client = TestClient(incident_app)
    headers = {"X-Tenant-Id": "tenant-demo", "X-Role": "analyst"}

    for finding in finding_payloads:
        created = client.post(
            "/api/v1/findings",
            headers=headers,
            json={
                "finding_id": finding["finding_id"],
                "finding_type": finding["finding_type"],
                "asset_id": finding["asset_id"],
                "service_id": finding["service_id"],
                "model_name": finding["model_name"],
                "model_version": finding["model_version"],
                "raw_score": finding["raw_score"],
                "calibrated_score": finding["calibrated_score"],
                "severity_hint": finding["severity_hint"],
                "window": finding["window"],
                "contributors": finding["contributors"],
                "evidence_refs": finding["evidence_refs"],
                "context": finding["context"],
                "fingerprint": finding["fingerprint"],
                "category": finding["category"],
            },
        )
        assert created.status_code == 201, created.text

    posted = client.post(
        "/api/v1/incidents",
        headers=headers,
        json={
            "incident_id": incident["incident_id"],
            "title": incident["title"],
            "status": incident["status"],
            "severity": incident["severity"],
            "risk_score": incident["risk_score"],
            "category": incident["category"],
            "first_seen": incident["first_seen"],
            "last_seen": incident["last_seen"],
            "assets": incident["assets"],
            "services": incident["services"],
            "finding_ids": incident["finding_ids"],
            "summary": incident["summary"],
            "models": incident["models"],
            "deployment_id": incident.get("deployment_id"),
            "commit": incident.get("commit"),
            "evidence": incident.get("evidence") or [],
            "context": incident.get("context") or {},
        },
    )
    assert posted.status_code == 201, posted.text
    body = posted.json()
    assert len(body["evidence"]) == 4
    assert body["deployment_id"] == "deploy-1"
    assert len(client.get("/api/v1/findings", headers=headers).json()["items"]) == 4

    incident_app.dependency_overrides.clear()
