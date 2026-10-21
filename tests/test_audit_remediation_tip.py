"""Focused tests for audit remediations F01, F03, F04, F05, F10 (TIP backend)."""

from __future__ import annotations

import asyncio
import io
import zipfile
from datetime import timedelta
from unittest.mock import MagicMock
from urllib.parse import parse_qs, urlsplit

import pytest
from fastapi.testclient import TestClient

from black_onyx.api.schemas import (
    MAX_GRAPH_BUILD_PAYLOADS,
    MAX_NESTED_DICT_BYTES,
    FeedAddRequest,
    GraphBuildRequest,
    PlaybookRunRequest,
    ReportGenerateRequest,
)
from black_onyx.automation.playbook_manager import PlaybookManager
from black_onyx.automation.runner import PlaybookRunner
from black_onyx.threat.detection_rules_manager import DetectionRulesManager


VALID_SIGMA = """
title: Audit Rem Test
id: 22222222-2222-2222-2222-222222222222
logsource:
  product: windows
detection:
  selection:
    Image|endswith: '\\\\cmd.exe'
  condition: selection
level: medium
"""

INVALID_SIGMA = "not: valid: [[[yaml"


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("QDRANT_STORAGE__STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("QDRANT_SECURITY__EXTERNAL_URL", "http://testserver")
    monkeypatch.setenv("BLACK_ONYX_AUTH_SECRET", "test-secret-that-is-long-and-random")
    monkeypatch.setenv("QDRANT_FEEDS__ENABLED", "false")
    monkeypatch.setenv("QDRANT_CONNECTORS__ENABLED", "false")
    from black_onyx.config import get_settings
    from black_onyx.auth.context import get_auth_service
    from black_onyx.api.service import AppService

    if AppService._instance is not None:
        AppService._instance._settings_store.database.close()
    AppService._instance = None
    AppService._initialized = False
    get_settings.cache_clear()
    get_auth_service.cache_clear()
    auth = get_auth_service()
    auth.bootstrap_admin("admin@example.com", "correct horse battery staple", "Admin")
    from black_onyx.api.app import create_app

    monkeypatch.setattr(AppService, "ensure_default_collections", lambda self: [])
    monkeypatch.setattr(AppService, "start_background_schedulers", lambda self: None)
    monkeypatch.setattr(AppService, "qdrant_store", property(lambda self: MagicMock()))
    with TestClient(create_app(), raise_server_exceptions=False) as test_client:
        yield test_client
    get_auth_service.cache_clear()
    get_settings.cache_clear()
    if AppService._instance is not None:
        AppService._instance._settings_store.database.close()
    AppService._instance = None
    AppService._initialized = False


@pytest.fixture
def authenticated(client: TestClient):
    response = client.post(
        "/api/v1/auth/login",
        headers={"Origin": "http://testserver"},
        json={"email": "admin@example.com", "password": "correct horse battery staple"},
    )
    assert response.status_code == 200
    csrf = response.json()["csrf_token"]
    client.headers.update({"Origin": "http://testserver", "X-CSRF-Token": csrf})
    return client


def _become_role(
    admin_client: TestClient,
    *,
    role: str,
    email: str,
    password: str = "another correct horse battery",
    display_name: str = "Role User",
) -> TestClient:
    invitation = admin_client.post(
        "/api/v1/admin/invitations",
        json={"email": email, "role": role, "send_email": False},
    )
    assert invitation.status_code == 200
    token = parse_qs(urlsplit(invitation.json()["invitation_url"]).query)["token"][0]
    admin_client.cookies.clear()
    registered = admin_client.post(
        "/api/v1/auth/register",
        json={"token": token, "display_name": display_name, "password": password},
    )
    assert registered.status_code == 200
    admin_client.headers["X-CSRF-Token"] = registered.json()["csrf_token"]
    assert registered.json()["user"]["role"] == role
    return admin_client


# --- F01 detection-rule approval ---


def test_f01_create_approved_rejected(authenticated: TestClient):
    resp = authenticated.post(
        "/api/v1/detection-rules",
        json={
            "name": "Bad Create",
            "rule_type": "sigma",
            "content": VALID_SIGMA,
            "status": "approved",
        },
    )
    assert resp.status_code == 422


def test_f01_analyst_cannot_self_approve_or_skip_validation(authenticated: TestClient):
    analyst = _become_role(
        authenticated, role="analyst", email="analyst1@example.com", display_name="Analyst One",
    )
    created = analyst.post(
        "/api/v1/detection-rules",
        json={"name": "Self Approve", "rule_type": "sigma", "content": VALID_SIGMA},
    )
    assert created.status_code == 200
    rule_id = created.json()["rule_id"]
    author = created.json()["author"]
    assert author

    skip_pending = analyst.patch(
        f"/api/v1/detection-rules/{rule_id}",
        json={"status": "approved"},
    )
    assert skip_pending.status_code == 422

    submitted = analyst.patch(
        f"/api/v1/detection-rules/{rule_id}",
        json={"status": "pending_approval"},
    )
    assert submitted.status_code == 200

    self_approve = analyst.patch(
        f"/api/v1/detection-rules/{rule_id}",
        json={"status": "approved"},
    )
    assert self_approve.status_code == 403


def test_f01_invalid_rule_cannot_be_approved_and_export_skips(tmp_path):
    mgr = DetectionRulesManager(persist_dir=str(tmp_path))
    try:
        with pytest.raises(ValueError, match="validation"):
            mgr.create_rule(
                "Invalid",
                "sigma",
                INVALID_SIGMA,
                author="analyst-a",
                status="pending_approval",
            )
        rule = mgr.create_rule(
            "Invalid",
            "sigma",
            INVALID_SIGMA,
            author="analyst-a",
            status="draft",
        )
        assert rule["validation_ok"] is False
        with pytest.raises(ValueError, match="validation"):
            mgr.update_rule(
                rule["rule_id"],
                actor_user_id="analyst-a",
                actor_is_admin=False,
                status="pending_approval",
            )
        with pytest.raises(ValueError, match="pending_approval"):
            mgr.update_rule(
                rule["rule_id"],
                actor_user_id="admin-1",
                actor_is_admin=True,
                status="approved",
            )

        # Force-approved invalid row must still be excluded from export.
        with mgr._lock:
            mgr._conn.execute(
                "UPDATE detection_rules SET status = 'approved', validation_ok = 0 WHERE rule_id = ?",
                (rule["rule_id"],),
            )
            mgr._conn.commit()
        package = mgr.export_package(status="approved")
        with zipfile.ZipFile(io.BytesIO(package)) as zf:
            assert zf.namelist() == []
    finally:
        mgr.close()


def test_f01_admin_or_second_analyst_can_approve(authenticated: TestClient):
    # Admin session creates rule as admin author, then submits and approves (admin bypasses SoD).
    created = authenticated.post(
        "/api/v1/detection-rules",
        json={"name": "Admin Approve", "rule_type": "sigma", "content": VALID_SIGMA},
    )
    assert created.status_code == 200
    rule_id = created.json()["rule_id"]
    authenticated.patch(f"/api/v1/detection-rules/{rule_id}", json={"status": "pending_approval"})
    approved = authenticated.patch(
        f"/api/v1/detection-rules/{rule_id}",
        json={"status": "approved"},
    )
    assert approved.status_code == 200
    assert approved.json()["status"] == "approved"
    assert approved.json()["approved_by"]

    # Second-analyst SoD: author analyst A, approver analyst B.
    analyst_a = _become_role(
        authenticated, role="analyst", email="author@example.com", display_name="Author",
    )
    created_b = analyst_a.post(
        "/api/v1/detection-rules",
        json={"name": "Peer Approve", "rule_type": "sigma", "content": VALID_SIGMA},
    )
    assert created_b.status_code == 200
    peer_id = created_b.json()["rule_id"]
    analyst_a.patch(f"/api/v1/detection-rules/{peer_id}", json={"status": "pending_approval"})

    # Re-login as admin to invite second analyst, then register as analyst B.
    authenticated.cookies.clear()
    login = authenticated.post(
        "/api/v1/auth/login",
        headers={"Origin": "http://testserver"},
        json={"email": "admin@example.com", "password": "correct horse battery staple"},
    )
    assert login.status_code == 200
    authenticated.headers["X-CSRF-Token"] = login.json()["csrf_token"]
    analyst_b = _become_role(
        authenticated,
        role="analyst",
        email="peer@example.com",
        display_name="Peer",
        password="peer correct horse battery",
    )
    peer_ok = analyst_b.patch(
        f"/api/v1/detection-rules/{peer_id}",
        json={"status": "approved"},
    )
    assert peer_ok.status_code == 200
    assert peer_ok.json()["status"] == "approved"
    assert peer_ok.json()["approved_by"]


# --- F03 graph/build bounds ---


def test_f03_graph_build_rejects_oversized_payload_list(authenticated: TestClient):
    too_many = [{"text": f"n{i}"} for i in range(MAX_GRAPH_BUILD_PAYLOADS + 1)]
    resp = authenticated.post("/api/v1/graph/build", json=too_many)
    assert resp.status_code == 422

    ok = authenticated.post("/api/v1/graph/build", json=[{"text": "hello", "ips": ["1.2.3.4"]}])
    assert ok.status_code == 200
    assert "nodes" in ok.json()


def test_f03_graph_build_request_model_caps_serialized_size():
    with pytest.raises(Exception):
        GraphBuildRequest.model_validate([{"blob": "x" * (MAX_NESTED_DICT_BYTES * 20)}] * 50)


# --- F04 rate limits ---


def test_f04_search_and_chat_rate_limited(authenticated: TestClient, monkeypatch):
    from black_onyx.api import routes as routes_mod
    from black_onyx.api.service import get_service

    monkeypatch.setattr(routes_mod, "_SEARCH_MAX", 2)
    monkeypatch.setattr(routes_mod, "_CHAT_MAX", 2)
    monkeypatch.setattr(routes_mod, "_SEARCH_WINDOW", timedelta(minutes=5))
    monkeypatch.setattr(routes_mod, "_CHAT_WINDOW", timedelta(minutes=5))
    routes_mod._SEARCH_LIMITER._events.clear()
    routes_mod._CHAT_LIMITER._events.clear()

    svc = get_service()
    store = MagicMock()
    store.search.return_value = []
    emb = MagicMock()
    emb.encode_search_query.return_value = [0.1, 0.2]
    emb.encode_single.return_value = [0.1, 0.2]
    monkeypatch.setattr(type(svc), "qdrant_store", property(lambda self: store))
    monkeypatch.setattr(type(svc), "embedding_model", property(lambda self: emb))

    llm = MagicMock()
    llm.chat.return_value = MagicMock(text="ok", model="test")
    monkeypatch.setattr(svc, "get_llm_provider", lambda *_a, **_k: llm)

    for _ in range(2):
        r = authenticated.post(
            "/api/v1/search",
            json={"query": "test", "collection": "all-knowledge", "limit": 5},
        )
        assert r.status_code == 200, r.text
    limited = authenticated.post(
        "/api/v1/search",
        json={"query": "test", "collection": "all-knowledge", "limit": 5},
    )
    assert limited.status_code == 429

    for _ in range(2):
        c = authenticated.post(
            "/api/v1/chat",
            json={"message": "hi", "use_rag": False},
        )
        assert c.status_code == 200, c.text
    chat_limited = authenticated.post(
        "/api/v1/chat",
        json={"message": "hi again", "use_rag": False},
    )
    assert chat_limited.status_code == 429


def test_f04_mcp_chat_uses_tighter_rate_limit(authenticated: TestClient, monkeypatch):
    from black_onyx.api import routes as routes_mod
    from black_onyx.api.service import get_service

    monkeypatch.setattr(routes_mod, "_CHAT_HEAVY_MAX", 1)
    monkeypatch.setattr(routes_mod, "_CHAT_WINDOW", timedelta(minutes=5))
    routes_mod._CHAT_LIMITER._events.clear()

    svc = get_service()
    monkeypatch.setattr(svc.settings.mcp_tools, "enabled", True)
    monkeypatch.setattr(svc.settings.web_search, "enabled", False)

    class _FakeOrch:
        def __init__(self, **_kwargs):
            pass

        async def run(self, *_args, **_kwargs):
            yield ("token", "ok")

    monkeypatch.setattr(
        "black_onyx.llm.mcp_orchestrator.McpToolOrchestrator",
        _FakeOrch,
    )
    llm = type("LLM", (), {"_model": "test-model"})()
    monkeypatch.setattr(svc, "get_llm_provider", lambda *_a, **_k: llm)

    first = authenticated.post(
        "/api/v1/chat",
        json={"message": "use tools", "use_rag": False, "use_mcp_tools": True},
    )
    assert first.status_code == 200, first.text
    second = authenticated.post(
        "/api/v1/chat",
        json={"message": "use tools again", "use_rag": False, "use_mcp_tools": True},
    )
    assert second.status_code == 429


# --- F05 playbook SoD + approved_by ---


def test_f05_playbook_approve_sod_and_stamp(tmp_path):
    mgr = PlaybookManager(persist_dir=str(tmp_path))
    try:
        playbook = mgr.create_playbook(
            "Needs Approval",
            "manual",
            [{"type": "wait_approval"}],
        )
        run = mgr.start_run(playbook["id"], {"iocs": {}}, initiated_by="user-a")
        runner = PlaybookRunner(playbook_manager=mgr)
        waiting = asyncio.run(runner.execute_run(run["run_id"]))
        assert waiting["status"] == "waiting_approval"
        assert waiting["initiated_by"] == "user-a"

        continued = asyncio.run(
            runner.continue_after_approval(run["run_id"], approved_by="user-b"),
        )
        assert mgr.get_run(run["run_id"])["approved_by"] == "user-b"
        assert continued["approved_by"] == "user-b"
    finally:
        mgr.close()


def test_f05_playbook_route_rejects_self_approve(authenticated: TestClient):
    created = authenticated.post(
        "/api/v1/playbooks",
        json={
            "name": "SoD Playbook",
            "trigger_type": "manual",
            "steps": [{"type": "wait_approval"}],
            "enabled": True,
        },
    )
    assert created.status_code == 200
    playbook_id = created.json()["id"]

    analyst = _become_role(
        authenticated,
        role="analyst",
        email="runner@example.com",
        display_name="Runner",
    )
    run_resp = analyst.post(f"/api/v1/playbooks/{playbook_id}/run", json={"context": {}})
    assert run_resp.status_code == 200
    run_id = run_resp.json()["run_id"]
    assert run_resp.json()["status"] == "waiting_approval"
    assert run_resp.json()["initiated_by"]

    self_approve = analyst.post(f"/api/v1/playbook-runs/{run_id}/approve")
    assert self_approve.status_code == 403


# --- F10 nested dict caps ---


def test_f10_nested_dict_size_caps():
    huge = {"pad": "x" * (MAX_NESTED_DICT_BYTES + 10)}
    with pytest.raises(Exception):
        PlaybookRunRequest(context=huge)
    with pytest.raises(Exception):
        FeedAddRequest(
            name="Huge",
            url="https://feeds.example.com/rss.xml",
            config=huge,
        )
    ok = PlaybookRunRequest(context={"alert_id": "a1"})
    assert ok.context["alert_id"] == "a1"
    with pytest.raises(Exception):
        ReportGenerateRequest(enrichments=[{"pad": "y" * 2000} for _ in range(400)])
    report_ok = ReportGenerateRequest(
        title="Bounded",
        enrichments=[{"provider": "otx", "score": 1}],
        mitre_techniques=[{"id": "T1059"}],
    )
    assert report_ok.enrichments and report_ok.mitre_techniques
