from datetime import datetime, timezone

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from incident_api.db import Base, get_db
from incident_api.main import app


def _client() -> TestClient:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    TestingSession = sessionmaker(bind=engine)
    Base.metadata.create_all(bind=engine)

    def override_db():
        db = TestingSession()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_db
    return TestClient(app)


def test_incident_returns_models_evidence_and_ops_catalog():
    client = _client()
    headers = {"X-Tenant-Id": "tenant-a", "X-Role": "analyst"}
    now = datetime.now(timezone.utc).isoformat()

    finding = client.post(
        "/api/v1/findings",
        headers=headers,
        json={
            "finding_id": "fnd-1",
            "finding_type": "log_anomaly",
            "asset_id": "host-1",
            "service_id": "payments-api",
            "model_name": "log-model",
            "raw_score": 0.9,
            "calibrated_score": 0.91,
            "severity_hint": "high",
            "window": {"start": now, "end": now},
            "contributors": [{"type": "template", "contribution": 0.8, "template_id": "auth"}],
            "context": {"deployment_id": "deploy-1", "commit": "abc123"},
        },
    )
    assert finding.status_code == 201

    created = client.post(
        "/api/v1/incidents",
        headers=headers,
        json={
            "title": "Evidence incident",
            "severity": "high",
            "risk_score": 0.88,
            "category": ["anomaly"],
            "first_seen": now,
            "last_seen": now,
            "assets": ["host-1"],
            "services": ["payments-api"],
            "finding_ids": ["fnd-1"],
            "summary": "demo",
            "models": ["log-model"],
            "deployment_id": "deploy-1",
            "commit": "abc123",
            "evidence": [
                {
                    "kind": "logs",
                    "model": "log-model",
                    "title": "log spike",
                    "detail": "auth template",
                    "score": 0.91,
                    "timestamp": now,
                }
            ],
        },
    )
    assert created.status_code == 201
    body = created.json()
    assert body["models"] == ["log-model"]
    assert body["deployment_id"] == "deploy-1"
    assert body["commit"] == "abc123"
    assert len(body["evidence"]) == 1
    assert body["evidence"][0]["kind"] == "logs"

    got = client.get(f"/api/v1/incidents/{body['incident_id']}", headers=headers)
    assert got.status_code == 200
    assert got.json()["evidence"][0]["model"] == "log-model"

    models = client.get("/api/v1/ops/models")
    assert models.status_code == 200
    assert any(m["model_id"] == "log-model" for m in models.json())

    health = client.get("/api/v1/ops/data-health")
    assert health.status_code == 200
    assert len(health.json()) >= 1
