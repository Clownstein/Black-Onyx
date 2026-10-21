"""MCP service-key auth: fail-closed, actor attach, CSRF/origin skip."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from black_onyx.auth.service import Role


@pytest.fixture
def mcp_client(tmp_path, monkeypatch):
    monkeypatch.setenv("QDRANT_STORAGE__STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("QDRANT_SECURITY__EXTERNAL_URL", "http://testserver")
    monkeypatch.setenv("BLACK_ONYX_AUTH_SECRET", "test-secret-that-is-long-and-random")
    monkeypatch.setenv("QDRANT_FEEDS__ENABLED", "false")
    monkeypatch.setenv("QDRANT_CONNECTORS__ENABLED", "false")
    monkeypatch.delenv("ALLOW_DEMO_KEYS", raising=False)
    monkeypatch.delenv("BLACK_ONYX_MCP_SERVICE_KEY", raising=False)
    monkeypatch.delenv("BLACK_ONYX_MCP_ACTOR_USER_ID", raising=False)

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
    admin = auth.bootstrap_admin(
        "admin@example.com", "correct horse battery staple", "Admin",
    )
    from black_onyx.api.app import create_app
    from unittest.mock import MagicMock

    monkeypatch.setattr(AppService, "ensure_default_collections", lambda self: [])
    monkeypatch.setattr(AppService, "start_background_schedulers", lambda self: None)
    monkeypatch.setattr(AppService, "qdrant_store", property(lambda self: MagicMock()))
    with TestClient(create_app(), raise_server_exceptions=False) as test_client:
        yield test_client, auth, admin
    get_auth_service.cache_clear()
    get_settings.cache_clear()
    if AppService._instance is not None:
        AppService._instance._settings_store.database.close()
    AppService._instance = None
    AppService._initialized = False


def test_mcp_key_unset_rejects_header(mcp_client):
    client, _auth, _admin = mcp_client
    response = client.get(
        "/api/v1/auth/me",
        headers={"X-MCP-Service-Key": "any-key-at-all"},
    )
    assert response.status_code == 401
    assert "MCP" in response.json()["title"]


def test_mcp_key_wrong_rejects(mcp_client, monkeypatch):
    client, _auth, admin = mcp_client
    monkeypatch.setenv("BLACK_ONYX_MCP_SERVICE_KEY", "correct-mcp-service-key-value")
    monkeypatch.setenv("BLACK_ONYX_MCP_ACTOR_USER_ID", admin.user_id)
    response = client.get(
        "/api/v1/auth/me",
        headers={"X-MCP-Service-Key": "wrong-mcp-service-key-value"},
    )
    assert response.status_code == 401


def test_mcp_key_attaches_actor_and_skips_csrf(mcp_client, monkeypatch):
    client, _auth, admin = mcp_client
    monkeypatch.setenv("BLACK_ONYX_MCP_SERVICE_KEY", "correct-mcp-service-key-value")
    monkeypatch.setenv("BLACK_ONYX_MCP_ACTOR_USER_ID", admin.user_id)

    me = client.get(
        "/api/v1/auth/me",
        headers={"X-MCP-Service-Key": "correct-mcp-service-key-value"},
    )
    assert me.status_code == 200
    body = me.json()["user"]
    assert body["user_id"] == admin.user_id
    assert body["role"] == "admin"

    # Mutating request without Origin/CSRF must succeed for MCP auth.
    response = client.post(
        "/api/v1/search",
        headers={"X-MCP-Service-Key": "correct-mcp-service-key-value"},
        json={"query": "test", "collection": "all-knowledge", "limit": 1},
    )
    # Search may 200 or 5xx depending on mocked qdrant; must not be 401/403 CSRF/origin.
    assert response.status_code not in {401, 403}


def test_mcp_demo_key_fail_closed_without_allow(mcp_client, monkeypatch):
    client, _auth, admin = mcp_client
    monkeypatch.setenv("BLACK_ONYX_MCP_SERVICE_KEY", "dev-mcp-key")
    monkeypatch.setenv("BLACK_ONYX_MCP_ACTOR_USER_ID", admin.user_id)
    monkeypatch.delenv("ALLOW_DEMO_KEYS", raising=False)
    response = client.get(
        "/api/v1/auth/me",
        headers={"X-MCP-Service-Key": "dev-mcp-key"},
    )
    assert response.status_code == 401


def test_mcp_demo_key_allowed_when_flag_set(mcp_client, monkeypatch):
    client, _auth, admin = mcp_client
    monkeypatch.setenv("BLACK_ONYX_MCP_SERVICE_KEY", "dev-mcp-key")
    monkeypatch.setenv("BLACK_ONYX_MCP_ACTOR_USER_ID", admin.user_id)
    monkeypatch.setenv("ALLOW_DEMO_KEYS", "true")
    response = client.get(
        "/api/v1/auth/me",
        headers={"X-MCP-Service-Key": "dev-mcp-key"},
    )
    assert response.status_code == 200
    assert response.json()["user"]["user_id"] == admin.user_id


def test_mcp_viewer_actor_rejected(mcp_client, monkeypatch):
    client, auth, admin = mcp_client
    token = auth.create_invitation(admin, "viewer@example.com", Role.VIEWER, hours=1)
    viewer = auth.register(token, "correct horse battery staple", "Viewer")
    monkeypatch.setenv("BLACK_ONYX_MCP_SERVICE_KEY", "correct-mcp-service-key-value")
    monkeypatch.setenv("BLACK_ONYX_MCP_ACTOR_USER_ID", viewer.user_id)
    response = client.get(
        "/api/v1/auth/me",
        headers={"X-MCP-Service-Key": "correct-mcp-service-key-value"},
    )
    assert response.status_code == 401


def test_mcp_missing_actor_user_id_rejects(mcp_client, monkeypatch):
    client, _auth, _admin = mcp_client
    monkeypatch.setenv("BLACK_ONYX_MCP_SERVICE_KEY", "correct-mcp-service-key-value")
    monkeypatch.delenv("BLACK_ONYX_MCP_ACTOR_USER_ID", raising=False)
    response = client.get(
        "/api/v1/auth/me",
        headers={"X-MCP-Service-Key": "correct-mcp-service-key-value"},
    )
    assert response.status_code == 401


def test_mcp_inactive_actor_rejected(mcp_client, monkeypatch):
    client, auth, admin = mcp_client
    token = auth.create_invitation(admin, "analyst@example.com", Role.ANALYST, hours=1)
    analyst = auth.register(token, "correct horse battery staple", "Analyst")
    auth.update_user(admin, analyst.user_id, role=None, active=False)
    monkeypatch.setenv("BLACK_ONYX_MCP_SERVICE_KEY", "correct-mcp-service-key-value")
    monkeypatch.setenv("BLACK_ONYX_MCP_ACTOR_USER_ID", analyst.user_id)
    response = client.get(
        "/api/v1/auth/me",
        headers={"X-MCP-Service-Key": "correct-mcp-service-key-value"},
    )
    assert response.status_code == 401
