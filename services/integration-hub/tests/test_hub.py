from __future__ import annotations

import pytest
from unittest.mock import ANY
from integration_hub.db import Base, get_db
from integration_hub.main import app
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool


@pytest.fixture()
def client() -> TestClient:
    engine = create_engine(
        "sqlite+pysqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    TestingSession = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    Base.metadata.create_all(bind=engine)

    def _override_db():
        db = TestingSession()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = _override_db
    with TestClient(app, headers={"X-API-Key": "dev-integration-key"}) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def test_thehive_dry_run_stores_payload(client: TestClient) -> None:
    resp = client.post(
        "/api/v1/thehive/cases",
        json={
            "incident": {
                "incident_id": "inc-1",
                "tenant_id": "tenant-acme",
                "title": "Suspicious egress",
                "severity": "high",
                "risk_score": 0.91,
                "summary": "multi-model",
                "assets": ["host-1"],
                "services": ["api"],
                "category": ["suspicious_egress"],
            }
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["dry_run"] is True
    assert body["operation"] == "create"
    assert body["payload"]["title"] == "Suspicious egress"
    assert "stored_id" in body

    listed = client.get("/api/v1/thehive/dry-runs")
    assert listed.status_code == 200
    assert len(listed.json()["items"]) >= 1


def test_response_request_and_approve_proxy(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[tuple[str, object]] = []

    def create_request(payload):
        calls.append(("create", payload))
        return {"request_id": "resp-1", "status": "pending", **payload}

    def approve_request(request_id, *, tenant_id, actor, dry_run):
        calls.append(("approve", (request_id, tenant_id, actor, dry_run)))
        return {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "approved_by": actor,
            "status": "completed",
        }

    def list_audit(tenant_id, limit):
        calls.append(("audit", (tenant_id, limit)))
        return {"items": [{"tenant_id": tenant_id, "action": "executed"}]}

    monkeypatch.setattr("integration_hub.response_client.create_request", create_request)
    monkeypatch.setattr("integration_hub.response_client.approve_request", approve_request)
    monkeypatch.setattr("integration_hub.response_client.list_audit", list_audit)

    created = client.post(
        "/api/v1/response/request",
        json={
            "tenant_id": "tenant-acme",
            "incident_id": "inc-2",
            "playbook_id": "packs/v1/block-ip-pfsense",
            "dry_run": True,
            "payload": {"ip": "203.0.113.10"},
        },
    )
    assert created.status_code == 200
    req = created.json()
    assert req["status"] == "pending"
    request_id = req["request_id"]

    approved = client.post(
        f"/api/v1/response/{request_id}/approve",
        json={"actor": "alice"},
        headers={"X-Tenant-Id": "tenant-acme"},
    )
    assert approved.status_code == 200
    body = approved.json()
    assert body["approved_by"] == "alice"
    assert body["status"] == "completed"

    audit = client.get("/api/v1/response/audit", params={"tenant_id": "tenant-acme"})
    assert audit.status_code == 200
    actions_audit = {i["action"] for i in audit.json()["items"]}
    assert "executed" in actions_audit
    assert calls == [
        ("create", ANY),
        ("approve", ("resp-1", "tenant-acme", "alice", None)),
        ("audit", ("tenant-acme", 100)),
    ]


def test_response_approval_requires_tenant(client: TestClient) -> None:
    response = client.post(
        "/api/v1/response/resp-1/approve",
        json={"actor": "alice"},
    )
    assert response.status_code == 400


def test_dfir_collect_queues(client: TestClient) -> None:
    resp = client.post(
        "/api/v1/dfir/collect",
        json={
            "tenant_id": "tenant-acme",
            "asset_id": "host-1",
            "incident_id": "inc-3",
            "artifact": "Windows.System.Pslist",
            "dry_run": True,
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "queued"
    assert body["dry_run"] is True
    assert body["request_id"].startswith("dfir-")
    assert body["detail"]["submission"]["dry_run"] is True
