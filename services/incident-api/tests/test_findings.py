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


def test_create_list_get_evidence_and_filters():
    client = _client()
    headers = {"X-Tenant-Id": "tenant-a", "X-Role": "analyst"}
    other = {"X-Tenant-Id": "tenant-b", "X-Role": "analyst"}
    now = datetime.now(timezone.utc).isoformat()
    payload = {
        "finding_id": "finding-log-1",
        "finding_type": "log_anomaly",
        "asset_id": "host-1",
        "service_id": "payments-api",
        "model_name": "log-transformer",
        "model_version": "1.3.0",
        "raw_score": 4.8,
        "calibrated_score": 0.94,
        "severity_hint": "high",
        "window": {"start": now, "end": now},
        "contributors": [{"type": "unexpected_template", "contribution": 0.4}],
        "evidence_refs": ["ev-1"],
        "context": {"deployment_id": "deploy-1"},
    }
    created = client.post("/api/v1/findings", json=payload, headers=headers)
    assert created.status_code == 201
    body = created.json()
    assert body["finding_id"] == "finding-log-1"
    assert body["calibrated_score"] == 0.94
    assert body["payload"]["tenant_id"] == "tenant-a"

    listed = client.get("/api/v1/findings", headers=headers)
    assert listed.status_code == 200
    assert len(listed.json()["items"]) == 1

    filtered = client.get(
        "/api/v1/findings",
        headers=headers,
        params={"type": "log_anomaly", "asset": "host-1", "service": "payments-api", "min_score": 0.9},
    )
    assert filtered.status_code == 200
    assert len(filtered.json()["items"]) == 1

    empty = client.get("/api/v1/findings", headers=headers, params={"min_score": 0.99})
    assert empty.json()["items"] == []

    isolated = client.get("/api/v1/findings", headers=other)
    assert isolated.json()["items"] == []

    got = client.get("/api/v1/findings/finding-log-1", headers=headers)
    assert got.status_code == 200
    assert got.json()["asset_id"] == "host-1"

    evidence = client.get("/api/v1/findings/finding-log-1/evidence", headers=headers)
    assert evidence.status_code == 200
    assert evidence.json()["evidence_refs"] == ["ev-1"]
    assert evidence.json()["contributors"][0]["type"] == "unexpected_template"

    upsert = client.post(
        "/api/v1/findings",
        json={**payload, "calibrated_score": 0.97},
        headers=headers,
    )
    assert upsert.status_code == 201
    assert upsert.json()["calibrated_score"] == 0.97
    assert len(client.get("/api/v1/findings", headers=headers).json()["items"]) == 1


def test_search_incidents_and_findings():
    client = _client()
    headers = {"X-Tenant-Id": "tenant-a", "X-Role": "analyst"}
    now = datetime.now(timezone.utc).isoformat()
    client.post(
        "/api/v1/incidents",
        json={
            "title": "Payments API contacted a new external peer",
            "severity": "high",
            "risk_score": 0.9,
            "first_seen": now,
            "last_seen": now,
            "services": ["payments-api"],
            "summary": "suspicious egress",
        },
        headers=headers,
    )
    client.post(
        "/api/v1/findings",
        json={
            "finding_type": "network_anomaly",
            "asset_id": "host-payments-03",
            "service_id": "payments-api",
            "model_name": "flow-transformer",
            "calibrated_score": 0.91,
            "window": {"start": now, "end": now},
        },
        headers=headers,
    )

    result = client.post(
        "/api/v1/search",
        json={"query": "payments", "types": ["incident", "finding"], "limit": 10},
        headers=headers,
    )
    assert result.status_code == 200
    types = {item["type"] for item in result.json()["items"]}
    assert "incident" in types
    assert "finding" in types
