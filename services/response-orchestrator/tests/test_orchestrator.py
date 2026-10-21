import pytest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from threading import Event
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from response_orchestrator.config import settings
from response_orchestrator.db import SessionLocal, init_db
from response_orchestrator.main import app
from response_orchestrator.models import Base, ResponseRequest
from response_orchestrator import response as response_service


def test_live_approval_cannot_race_rejection_or_repeat(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'responses.db'}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine)
    with sessions() as db:
        row = response_service.create_request(
            db, tenant_id="tenant-a", incident_id="inc-race", playbook_id="capture-now",
            actor="analyst", payload={"asset_id": "sensor-1"},
        )
        request_id = row.request_id
    entered, release = Event(), Event()
    calls: list[str] = []

    def fake_playbook(*_args, **_kwargs):
        calls.append("live")
        entered.set()
        assert release.wait(5)
        return {"executed": True, "steps": []}

    monkeypatch.setattr(response_service, "execute_playbook", fake_playbook)

    def approve():
        with sessions() as db:
            return response_service.approve_request(
                db, request_id=request_id, actor="admin", tenant_id="tenant-a",
                dry_run_override=False, allow_live_override=True,
            ).status

    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(approve)
        assert entered.wait(5)
        with sessions() as db:
            with pytest.raises(ValueError):
                response_service.reject_request(db, request_id=request_id, tenant_id="tenant-a")
        with sessions() as db:
            with pytest.raises(ValueError):
                response_service.approve_request(db, request_id=request_id, actor="admin",
                                                 tenant_id="tenant-a", dry_run_override=False,
                                                 allow_live_override=True)
        release.set()
        assert pending.result(timeout=5) == "approved_live"
    assert calls == ["live"]


def test_interrupted_execution_requires_reconciliation_and_never_replays(monkeypatch):
    init_db()
    with TestClient(app) as client:
        headers = {"X-API-Key": "dev-response-key", "X-Tenant-Id": "tenant-a"}
        created = client.post(
            "/api/v1/response/request", headers=headers,
            json={"tenant_id": "tenant-a", "incident_id": "inc-interrupted",
                  "playbook_id": "capture-now", "payload": {"asset_id": "sensor-1"},
                  "actor": "analyst"},
        ).json()
        request_id = created["request_id"]
        with SessionLocal() as db:
            row = db.query(ResponseRequest).filter_by(request_id=request_id).one()
            row.status = "executing"
            row.updated_at = datetime.now(timezone.utc) - timedelta(hours=2)
            db.commit()

        called: list[str] = []
        monkeypatch.setattr(response_service, "execute_playbook", lambda *_a, **_kw: called.append("run"))
        forbidden = client.get("/api/v1/response/reconciliation", headers=headers)
        assert forbidden.status_code == 403
        other = client.get(
            "/api/v1/response/reconciliation",
            headers={**headers, "X-Tenant-Id": "tenant-b", "X-Approver-Key": "approver-test-key"},
        )
        assert other.status_code == 200
        assert other.json()["items"] == []
        read_only = client.get(
            "/api/v1/response/reconciliation",
            headers={**headers, "X-Approver-Key": "approver-test-key"},
        )
        assert read_only.status_code == 200
        assert read_only.json()["items"] == []
        reconciled = client.post(
            "/api/v1/response/reconciliation/scan",
            headers={**headers, "X-Approver-Key": "approver-test-key"},
        )
        assert reconciled.status_code == 200
        assert reconciled.json()["items"][0]["status"] == "execution_uncertain"
        assert reconciled.json()["items"][0]["result"]["executed"] is None
        repeated = client.post(
            f"/api/v1/response/{request_id}/approve", headers=headers,
            json={"actor": "admin"},
        )
        assert repeated.status_code == 409
        assert called == []
        audit = client.get("/api/v1/response/audit", headers=headers).json()["items"]
        assert sum(entry["action"] == "execution_uncertain" for entry in audit) == 1


def test_reconciliation_cannot_be_overwritten_by_late_adapter_result(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'late.db'}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine)
    with sessions() as db:
        request_id = response_service.create_request(
            db, tenant_id="tenant-a", incident_id="inc-late", playbook_id="capture-now",
            actor="analyst", payload={"asset_id": "sensor-1"},
        ).request_id

    entered, release = Event(), Event()
    def slow_playbook(*_args, **_kwargs):
        entered.set()
        assert release.wait(5)
        return {"executed": True, "steps": []}

    monkeypatch.setattr(response_service, "execute_playbook", slow_playbook)
    def approve():
        with sessions() as db:
            return response_service.approve_request(
                db, request_id=request_id, actor="admin", tenant_id="tenant-a",
                dry_run_override=False, allow_live_override=True,
            ).status

    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(approve)
        assert entered.wait(5)
        with sessions() as db:
            row = db.query(ResponseRequest).filter_by(request_id=request_id).one()
            row.updated_at = datetime.now(timezone.utc) - timedelta(hours=2)
            db.commit()
        with sessions() as db:
            uncertain = response_service.reconcile_stale_executions(db, tenant_id="tenant-a")
            assert [row.status for row in uncertain] == ["execution_uncertain"]
        release.set()
        assert pending.result(timeout=5) == "execution_uncertain"
    with sessions() as db:
        assert db.query(ResponseRequest).filter_by(request_id=request_id).one().status == "execution_uncertain"


@pytest.fixture(autouse=True)
def configured_service_keys():
    old_api_key = settings.api_key
    old_approver_key = settings.approver_api_key
    old_capture_url = settings.capture_api_url
    settings.api_key = "dev-response-key"
    settings.approver_api_key = "approver-test-key"
    settings.capture_api_url = ""
    try:
        yield
    finally:
        settings.api_key = old_api_key
        settings.approver_api_key = old_approver_key
        settings.capture_api_url = old_capture_url


def test_health():
    init_db()
    with TestClient(app) as client:
        assert client.get("/health/live").json()["status"] == "alive"
        assert client.get("/health/ready").json()["status"] == "ready"


def test_request_rejects_conflicting_tenant_header(monkeypatch):
    called = []
    monkeypatch.setattr(response_service, "create_request", lambda *_a, **_kw: called.append(True))
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/response/request",
            headers={"X-API-Key": "dev-response-key", "X-Tenant-Id": "tenant-a"},
            json={
                "tenant_id": "tenant-b", "incident_id": "inc-1",
                "playbook_id": "capture-now", "actor": "analyst",
            },
        )
    assert response.status_code == 403
    assert called == []


def test_readiness_fails_closed_without_api_key():
    old_api_key = settings.api_key
    settings.api_key = ""
    try:
        with TestClient(app) as client:
            assert client.get("/health/ready").status_code == 503
    finally:
        settings.api_key = old_api_key


def test_asset_scoped_playbook_requires_asset_at_creation():
    init_db()
    with TestClient(app) as client:
        headers = {"X-API-Key": "dev-response-key", "X-Tenant-Id": "tenant-a"}
        books = {b["id"]: b for b in client.get("/api/v1/playbooks", headers=headers).json()["items"]}
        assert books["isolate-host"]["asset_scoped"] is True
        assert books["capture-now"]["asset_scoped"] is True
        assert books["block-c2"]["asset_scoped"] is False
        missing = client.post(
            "/api/v1/response/request", headers=headers,
            json={"tenant_id": "tenant-a", "incident_id": "inc-1", "playbook_id": "isolate-host",
                  "payload": {}, "actor": "analyst-1"},
        )
        assert missing.status_code == 422
        assert "requires payload.asset_id" in missing.json()["detail"]
        ok = client.post(
            "/api/v1/response/request", headers=headers,
            json={"tenant_id": "tenant-a", "incident_id": "inc-1", "playbook_id": "block-c2",
                  "payload": {"ip": "8.8.8.8"}, "actor": "analyst-1"},
        )
        assert ok.status_code == 200


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


def test_caller_supplied_policy_cannot_create_live_request():
    init_db()
    with TestClient(app) as client:
        created = client.post(
            "/api/v1/response/request",
            headers={"X-API-Key": "dev-response-key", "X-Tenant-Id": "tenant-a"},
            json={
                "tenant_id": "tenant-a",
                "incident_id": "inc-forged-policy",
                "playbook_id": "capture-now",
                "dry_run": False,
                "payload": {
                    "asset_id": "sensor-1",
                    "signals": {
                        "exact_ti": True,
                        "vector_similarity": True,
                        "calibrated_score": 0.99,
                    },
                    "tenant_policy": {"soar.auto_vector_multi_signal": True},
                },
                "actor": "analyst",
            },
        )
        assert created.status_code == 200
        assert created.json()["dry_run"] is True
        assert created.json()["payload"]["auto_execute"] is False


def test_live_adapter_failure_is_not_reported_as_success():
    init_db()
    with TestClient(app) as client:
        headers = {"X-API-Key": "dev-response-key", "X-Tenant-Id": "tenant-a"}
        created = client.post(
            "/api/v1/response/request",
            headers=headers,
            json={
                "tenant_id": "tenant-a",
                "incident_id": "inc-live-failure",
                "playbook_id": "capture-now",
                "payload": {"asset_id": "sensor-1"},
                "actor": "analyst",
            },
        ).json()
        approved = client.post(
            f"/api/v1/response/{created['request_id']}/approve",
            headers={**headers, "X-Approver-Key": "approver-test-key"},
            json={"actor": "admin", "dry_run": False},
        )
        assert approved.status_code == 200
        body = approved.json()
        assert body["status"] == "failed"
        assert body["result"]["steps"][1]["result"]["ok"] is False
