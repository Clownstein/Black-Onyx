from fastapi.testclient import TestClient

from response_orchestrator.db import init_db
from response_orchestrator.main import app


def test_health():
    init_db()
    with TestClient(app) as client:
        assert client.get("/health/live").json()["status"] == "alive"
        assert client.get("/health/ready").json()["status"] == "ready"


def test_request_requires_approval_and_dry_run_default():
    init_db()
    with TestClient(app) as client:
        headers = {"X-API-Key": "dev-response-key", "X-Tenant-Id": "tenant-a"}
        created = client.post(
            "/api/v1/response/request",
            headers=headers,
            json={
                "tenant_id": "tenant-a",
                "incident_id": "inc-1",
                "playbook_id": "capture-now",
                "payload": {"asset_id": "sensor-1", "ip": "203.0.113.10"},
                "actor": "analyst-1",
            },
        )
        assert created.status_code == 200
        body = created.json()
        assert body["status"] == "pending"
        assert body["dry_run"] is True
        assert body["approval_required"] is True

        approved = client.post(
            f"/api/v1/response/{body['request_id']}/approve",
            headers=headers,
            json={"actor": "analyst-1"},
        )
        assert approved.status_code == 200
        result = approved.json()
        assert result["status"] == "completed"
        assert result["result"]["dry_run"] is True
        assert any(s.get("action") == "capture_now" for s in result["result"]["steps"])


def test_block_c2_dry_run():
    init_db()
    with TestClient(app) as client:
        headers = {"X-API-Key": "dev-response-key", "X-Tenant-Id": "tenant-a"}
        created = client.post(
            "/api/v1/response/request",
            headers=headers,
            json={
                "tenant_id": "tenant-a",
                "incident_id": "inc-2",
                "playbook_id": "block-c2",
                "payload": {"ip": "8.8.8.8", "domain": "evil.example"},
                "actor": "analyst-1",
            },
        ).json()
        approved = client.post(
            f"/api/v1/response/{created['request_id']}/approve",
            headers=headers,
            json={"actor": "admin"},
        ).json()
        assert approved["status"] == "completed"
        assert approved["result"]["executed"] is True


def test_approve_requires_tenant():
    init_db()
    with TestClient(app) as client:
        headers = {"X-API-Key": "dev-response-key", "X-Tenant-Id": "tenant-a"}
        created = client.post(
            "/api/v1/response/request",
            headers=headers,
            json={
                "tenant_id": "tenant-a",
                "incident_id": "inc-3",
                "playbook_id": "capture-now",
                "payload": {"asset_id": "sensor-1"},
                "actor": "analyst-1",
            },
        ).json()
        missing = client.post(
            f"/api/v1/response/{created['request_id']}/approve",
            headers={"X-API-Key": "dev-response-key"},
            json={"actor": "analyst"},
        )
        assert missing.status_code == 400
        wrong = client.post(
            f"/api/v1/response/{created['request_id']}/approve",
            headers={"X-API-Key": "dev-response-key", "X-Tenant-Id": "other"},
            json={"actor": "analyst"},
        )
        # Do not disclose that a request exists in another tenant.
        assert wrong.status_code == 404


def test_auth_required():
    init_db()
    with TestClient(app) as client:
        resp = client.post(
            "/api/v1/response/request",
            json={
                "tenant_id": "t",
                "incident_id": "i",
                "playbook_id": "block-ip-pfsense",
                "payload": {"ip": "203.0.113.1"},
                "actor": "analyst-1",
            },
        )
        assert resp.status_code == 401


def test_mutations_require_explicit_actor():
    init_db()
    with TestClient(app) as client:
        headers = {"X-API-Key": "dev-response-key", "X-Tenant-Id": "tenant-a"}
        missing = client.post(
            "/api/v1/response/request",
            headers=headers,
            json={
                "tenant_id": "tenant-a",
                "incident_id": "inc-no-actor",
                "playbook_id": "capture-now",
            },
        )
        assert missing.status_code == 422
