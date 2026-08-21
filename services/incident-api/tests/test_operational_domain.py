from datetime import datetime, timezone

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from incident_api.db import Base, get_db
from incident_api.deployment_consumer import _deployment_from_envelope
from incident_api.main import app


def _client() -> TestClient:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    testing_session = sessionmaker(bind=engine)
    Base.metadata.create_all(bind=engine)

    def override_db():
        db = testing_session()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_db
    return TestClient(app)


def test_deployments_feedback_settings_saved_hunts_and_audit_are_tenant_scoped() -> None:
    client = _client()
    headers = {"X-Tenant-Id": "tenant-a", "X-Role": "admin"}
    now = datetime.now(timezone.utc).isoformat()

    incident = client.post(
        "/api/v1/incidents",
        headers=headers,
        json={
            "title": "Operational domain",
            "severity": "high",
            "risk_score": 0.8,
            "first_seen": now,
            "last_seen": now,
            "assets": ["asset-a"],
            "services": ["payments"],
            "finding_ids": [],
        },
    )
    assert incident.status_code == 201
    incident_id = incident.json()["incident_id"]

    deployment = client.post(
        "/api/v1/deployments",
        headers=headers,
        json={
            "deployment_id": "dep-1",
            "service_id": "payments",
            "environment": "production",
            "commit_sha": "abc123",
            "version": "1.2.3",
            "status": "succeeded",
            "deployed_at": now,
        },
    )
    assert deployment.status_code == 201
    assert deployment.json()["tenant_id"] == "tenant-a"
    assert client.get(
        "/api/v1/deployments", headers={"X-Tenant-Id": "tenant-b"}
    ).json() == []

    saved = client.post(
        "/api/v1/saved-hunts",
        headers=headers,
        json={"name": "Payment anomalies", "query": "payments", "query_type": "text"},
    )
    assert saved.status_code == 201

    setting = client.put(
        "/api/v1/settings/notifications/email-primary",
        headers=headers,
        json={
            "setting_id": "email-primary",
            "channel": "email",
            "enabled": True,
            "config": {"recipient": "soc@example.test", "password": "do-not-return"},
        },
    )
    assert setting.status_code == 200
    assert setting.json()["config"]["password"] == "***"

    feedback = client.post(
        f"/api/v1/incidents/{incident_id}/feedback",
        headers=headers,
        json={"label": "expected_change", "note": "approved release"},
    )
    assert feedback.status_code == 201
    assert feedback.json()["incident_id"] == incident_id

    timeline = client.get(
        f"/api/v1/incidents/{incident_id}/timeline", headers=headers
    ).json()
    assert any(item["event_type"] == "analyst_feedback" for item in timeline)

    audit = client.get("/api/v1/audit", headers=headers)
    assert audit.status_code == 200
    resources = {(item["resource_type"], item["action"]) for item in audit.json()["items"]}
    assert ("deployment", "deployment_upserted") in resources
    assert ("notification_setting", "updated") in resources


def test_deployment_envelope_maps_commit_and_completion_time() -> None:
    tenant_id, body = _deployment_from_envelope(
        {
            "tenant_id": "tenant-acme",
            "timestamp": "2026-07-27T12:00:00Z",
            "payload": {
                "deployment_id": "dep-stream-1",
                "service_id": "payments",
                "environment": "production",
                "commit": "abc123",
                "version": "2.1.0",
                "status": "succeeded",
                "completed_at": "2026-07-27T11:59:00Z",
            },
        }
    )
    assert tenant_id == "tenant-acme"
    assert body.deployment_id == "dep-stream-1"
    assert body.commit_sha == "abc123"
    assert body.deployed_at.isoformat().startswith("2026-07-27T11:59:00")
