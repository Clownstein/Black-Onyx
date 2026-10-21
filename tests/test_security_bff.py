"""Tests for the security BFF proxy routes."""

from __future__ import annotations

from unittest.mock import patch

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from black_onyx.auth.service import Principal, Role


@pytest.fixture(autouse=True)
def _set_auth_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    """Set the auth secret required by the crypto module."""
    monkeypatch.setenv("BLACK_ONYX_AUTH_SECRET", "test-secret-for-bff-tests")
    monkeypatch.setenv("SECURITY_GATEWAY_KEY", "test-gateway-key-with-at-least-32-characters")


@pytest.fixture
def app() -> FastAPI:
    """Build a minimal FastAPI app with the security router mounted."""
    from black_onyx.api.routes_security import security_router

    application = FastAPI()
    application.include_router(security_router)
    return application


@pytest.fixture
def viewer_principal() -> Principal:
    return Principal("u-viewer", "viewer@test", "Viewer", Role.VIEWER)


@pytest.fixture
def analyst_principal() -> Principal:
    return Principal("u-analyst", "analyst@test", "Analyst", Role.ANALYST)


def _override_principal(app: FastAPI, principal: Principal) -> None:
    """Override only current_principal; let role-checking dependencies run."""
    from black_onyx.auth.dependencies import current_principal
    app.dependency_overrides[current_principal] = lambda: principal


@pytest.mark.asyncio
async def test_security_health(app: FastAPI, viewer_principal: Principal) -> None:
    """The health endpoint returns ok without exposing internal gateway hosts."""
    _override_principal(app, viewer_principal)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/v1/security/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["gateway_configured"] is True
    assert "gateway_url" not in data


@pytest.mark.asyncio
async def test_agent_run_requires_analyst(
    app: FastAPI, viewer_principal: Principal
) -> None:
    """The agent/run endpoint rejects viewers (requires analyst+)."""
    _override_principal(app, viewer_principal)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post("/api/v1/security/agent/run", json={"message": "test"})
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_chat_completions_requires_analyst(
    app: FastAPI, viewer_principal: Principal
) -> None:
    """The chat/completions endpoint rejects viewers."""
    _override_principal(app, viewer_principal)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/api/v1/security/chat/completions", json={"messages": []}
        )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_case_ioc_callback_requires_signed_analyst_and_is_actor_bound(
    app: FastAPI, analyst_principal: Principal, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from black_onyx.api import routes_security
    from black_onyx.api.routes_security import _security_token

    calls: list[tuple[str, str, str]] = []

    class CaseManager:
        def get_case(self, case_id: str):
            return {"case_id": case_id}

        def add_ioc_to_case(self, case_id: str, ioc_type: str, ioc_value: str) -> None:
            calls.append((case_id, ioc_type, ioc_value))

    class Service:
        case_manager = CaseManager()

    monkeypatch.setattr("black_onyx.api.service.get_service", lambda: Service())
    monkeypatch.setattr(routes_security._audit, "log_tool_call", lambda *a, **k: None)
    monkeypatch.setattr(routes_security._audit, "log_tool_result", lambda *a, **k: None)
    token = _security_token(analyst_principal)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        accepted = await client.post(
            "/api/v1/security/internal/cases/case-1/iocs",
            headers={"Authorization": f"Bearer {token}"},
            json={"ioc_type": "ipv4", "ioc_value": "8.8.8.8"},
        )
        forged = await client.post(
            "/api/v1/security/internal/cases/case-1/iocs",
            headers={"Authorization": "Bearer forged"},
            json={"ioc_type": "ipv4", "ioc_value": "8.8.8.8"},
        )
    assert accepted.status_code == 200
    assert calls == [("case-1", "ipv4", "8.8.8.8")]
    assert forged.status_code == 401


@pytest.mark.asyncio
async def test_proxy_rejects_traversal(
    app: FastAPI, analyst_principal: Principal
) -> None:
    """The proxy rejects paths with dot-dot traversal in the path segment."""
    _override_principal(app, analyst_principal)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # FastAPI normalizes ../ in the path, so use an encoded form
        resp = await client.post(
            "/api/v1/security/tools/%2e%2e/etc/passwd"
        )
    # The BFF rejects traversal attempts (encoded or not)
    assert resp.status_code in (400, 404)


def test_security_token_derivation(analyst_principal: Principal) -> None:
    """The security token is a signed gateway assertion."""
    with patch.dict("os.environ", {
        "BLACK_ONYX_AUTH_SECRET": "test-secret",
        "BLACK_ONYX_AUTH_SECRET_ENV": "BLACK_ONYX_AUTH_SECRET",
    }):
        from black_onyx.api.routes_security import _security_token
        token = _security_token(analyst_principal)
    assert token.count(".") == 1
    assert len(token) > 64


def test_security_token_rotates_with_time(analyst_principal: Principal) -> None:
    """The security token changes across time windows."""
    with patch.dict("os.environ", {
        "BLACK_ONYX_AUTH_SECRET": "test-secret",
        "BLACK_ONYX_AUTH_SECRET_ENV": "BLACK_ONYX_AUTH_SECRET",
    }):
        from black_onyx.api.routes_security import _security_token
        token1 = _security_token(analyst_principal)
        # Mock a different time window
        with patch("black_onyx.api.routes_security.time.time", return_value=999999999):
            token2 = _security_token(analyst_principal)
    assert token1 != token2


def test_security_token_differs_per_principal(
    analyst_principal: Principal, viewer_principal: Principal
) -> None:
    """Different principals get different tokens."""
    with patch.dict("os.environ", {
        "BLACK_ONYX_AUTH_SECRET": "test-secret",
        "BLACK_ONYX_AUTH_SECRET_ENV": "BLACK_ONYX_AUTH_SECRET",
    }):
        from black_onyx.api.routes_security import _security_token
        token1 = _security_token(analyst_principal)
        token2 = _security_token(viewer_principal)
    assert token1 != token2


def test_security_internal_ioc_callback_is_bearer_token_ingest() -> None:
    from starlette.requests import Request

    from black_onyx.auth.middleware import _is_token_ingest_request

    def make_request(path: str, authorization: bytes | None) -> Request:
        headers = [(b"authorization", authorization)] if authorization is not None else []
        return Request({
            "type": "http",
            "method": "POST",
            "path": path,
            "headers": headers,
        })

    assert _is_token_ingest_request(
        make_request("/api/v1/security/internal/cases/case-1/iocs", b"Bearer signed"),
    )
    assert not _is_token_ingest_request(
        make_request("/api/v1/security/internal/cases/case-1/iocs", None),
    )
    assert not _is_token_ingest_request(
        make_request("/api/v1/security/tools/add_ioc_to_case", b"Bearer signed"),
    )
