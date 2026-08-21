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


def test_create_list_disposition_tenant_isolation():
    client = _client()
    headers_a = {"X-Tenant-Id": "tenant-a", "X-Role": "analyst"}
    headers_b = {"X-Tenant-Id": "tenant-b", "X-Role": "analyst"}
    now = datetime.now(timezone.utc).isoformat()
    payload = {
        "title": "Test incident",
        "severity": "high",
        "risk_score": 0.9,
        "category": ["anomaly"],
        "first_seen": now,
        "last_seen": now,
        "assets": ["host-1"],
        "services": ["payments-api"],
        "finding_ids": ["f1"],
        "summary": "demo",
    }
    created = client.post("/api/v1/incidents", json=payload, headers=headers_a)
    assert created.status_code == 201
    incident_id = created.json()["incident_id"]

    listed_a = client.get("/api/v1/incidents", headers=headers_a)
    assert listed_a.status_code == 200
    assert len(listed_a.json()["items"]) == 1

    listed_b = client.get("/api/v1/incidents", headers=headers_b)
    assert listed_b.status_code == 200
    assert listed_b.json()["items"] == []

    other = client.get(f"/api/v1/incidents/{incident_id}", headers=headers_b)
    assert other.status_code == 404

    disp = client.post(
        f"/api/v1/incidents/{incident_id}/disposition",
        json={"disposition": "false_positive"},
        headers=headers_a,
    )
    assert disp.status_code == 200
    assert disp.json()["disposition"] == "false_positive"


def test_list_incidents_filters_by_site_id():
    client = _client()
    headers = {"X-Tenant-Id": "tenant-a", "X-Role": "analyst"}
    now = datetime.now(timezone.utc).isoformat()
    base = {
        "severity": "medium",
        "risk_score": 0.5,
        "category": ["anomaly"],
        "first_seen": now,
        "last_seen": now,
        "assets": ["host-1"],
        "services": [],
        "finding_ids": [],
    }
    a = client.post(
        "/api/v1/incidents",
        headers=headers,
        json={**base, "title": "site-a", "context": {"site_id": "plant-a"}},
    )
    b = client.post(
        "/api/v1/incidents",
        headers=headers,
        json={**base, "title": "site-b", "context": {"site_id": "plant-b"}},
    )
    assert a.status_code == 201
    assert b.status_code == 201

    filtered = client.get("/api/v1/incidents", headers=headers, params={"site_id": "plant-a"})
    assert filtered.status_code == 200
    items = filtered.json()["items"]
    assert len(items) == 1
    assert items[0]["title"] == "site-a"
    assert items[0]["context"]["site_id"] == "plant-a"
