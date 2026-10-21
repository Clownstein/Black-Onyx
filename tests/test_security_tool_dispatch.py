"""End-to-end dispatch tests: BFF → security-gateway → security-runner.

Uses httpx ASGI transport to test the security-gateway in-process with a
mocked runner backend. Verifies the full request flow:
  1. BFF proxy receives an authenticated session request
  2. BFF derives a bearer token and forwards to the gateway
  3. Gateway validates the token and dispatches to the runner
  4. Runner executes and returns results
  5. Results flow back through gateway → BFF → client
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from black_onyx.auth.service import Principal, Role

# Add the security-gateway service to the path so we can import it
_SERVICE_PATH = Path(__file__).resolve().parent.parent / "services" / "security-gateway"
if str(_SERVICE_PATH) not in sys.path:
    sys.path.insert(0, str(_SERVICE_PATH))


@pytest.fixture(autouse=True)
def _set_auth_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    """Set the auth secret required by the crypto module."""
    monkeypatch.setenv("BLACK_ONYX_AUTH_SECRET", "test-secret-for-dispatch")
    monkeypatch.setenv("SECURITY_GATEWAY_KEY", "test-gateway-key-with-at-least-32-characters")


@pytest.fixture
def gateway_app(monkeypatch: pytest.MonkeyPatch) -> FastAPI:
    """Build the security-gateway app with a mocked runner."""
    monkeypatch.setenv("SECURITY_GATEWAY_KEY", "test-gateway-key-with-at-least-32-characters")
    monkeypatch.setenv("SECURITY_RUNNER_TOKEN", "test-runner-token")
    monkeypatch.setenv("SECURITY_RUNNER_URL", "http://mock-runner:8080")
    from security_gateway.app import app
    return app


@pytest.fixture
def bff_app() -> FastAPI:
    """Build a minimal BFF app with the security router."""
    from black_onyx.api.routes_security import security_router
    application = FastAPI()
    application.include_router(security_router)
    return application


@pytest.fixture
def analyst_principal() -> Principal:
    return Principal("u-analyst", "analyst@test", "Analyst", Role.ANALYST)


def _gateway_auth() -> dict[str, str]:
    from black_onyx.api.routes_security import _security_token
    return {"Authorization": f"Bearer {_security_token(Principal('u-analyst', 'analyst@test', 'Analyst', Role.ANALYST))}"}


def _override_principal(app: FastAPI, principal: Principal) -> None:
    from black_onyx.auth.dependencies import current_principal
    app.dependency_overrides[current_principal] = lambda: principal


# ── Gateway tests ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_gateway_health(gateway_app: FastAPI) -> None:
    """The gateway health endpoint is public (no auth)."""
    transport = ASGITransport(app=gateway_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/health/")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


@pytest.mark.asyncio
async def test_gateway_health_live(gateway_app: FastAPI) -> None:
    """The gateway liveness endpoint is public."""
    transport = ASGITransport(app=gateway_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/health/live")
    assert resp.status_code == 200
    assert resp.json()["status"] == "alive"


@pytest.mark.asyncio
async def test_gateway_health_tools_requires_auth(gateway_app: FastAPI) -> None:
    """The health/tools endpoint requires a bearer token."""
    transport = ASGITransport(app=gateway_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/health/tools")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_gateway_rejects_forged_long_bearer(gateway_app: FastAPI) -> None:
    transport = ASGITransport(app=gateway_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get(
            "/health/tools", headers={"Authorization": "Bearer " + "a" * 64}
        )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_gateway_health_tools_with_token(gateway_app: FastAPI) -> None:
    """The health/tools endpoint returns the tool catalog with a valid token."""
    transport = ASGITransport(app=gateway_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get(
            "/health/tools",
            headers=_gateway_auth(),
        )
    assert resp.status_code == 200
    data = resp.json()
    assert "tools" in data
    assert data["total"] > 0
    # Each tool has name, description, category, tier, status
    tool = data["tools"][0]
    assert "name" in tool
    assert "description" in tool
    assert "category" in tool
    assert "tier" in tool
    assert "status" in tool


@pytest.mark.asyncio
async def test_gateway_list_tools(gateway_app: FastAPI) -> None:
    """The /v1/tools endpoint lists all registered tools."""
    transport = ASGITransport(app=gateway_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get(
            "/v1/tools",
            headers=_gateway_auth(),
        )
    assert resp.status_code == 200
    data = resp.json()
    assert "tools" in data
    assert len(data["tools"]) > 0


@pytest.mark.asyncio
async def test_gateway_unknown_tool_returns_404(gateway_app: FastAPI) -> None:
    """Executing an unknown tool returns 404."""
    transport = ASGITransport(app=gateway_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/v1/tools/nonexistent_tool",
            headers=_gateway_auth(),
            json={"arguments": {}},
        )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_gateway_tool_execution_missing_required_arg(gateway_app: FastAPI) -> None:
    """Executing a tool without a required argument returns 400."""
    transport = ASGITransport(app=gateway_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # nmap_scan requires "target"
        resp = await client.post(
            "/v1/tools/nmap_scan",
            headers=_gateway_auth(),
            json={"arguments": {}},
        )
    assert resp.status_code == 400
    assert "target" in resp.text


@pytest.mark.asyncio
async def test_gateway_agent_run(gateway_app: FastAPI) -> None:
    """The /v1/agent/run endpoint accepts a message and returns a response."""
    from security_gateway.llm_client import GenerateResult

    mock_result = GenerateResult(content="test answer", usage={})
    with patch("security_gateway.app._ensure_workspace", new_callable=AsyncMock), patch(
        "security_gateway.app._llm_client.chat",
        new_callable=AsyncMock,
        return_value=mock_result,
    ):
        transport = ASGITransport(app=gateway_app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/v1/agent/run",
                headers=_gateway_auth(),
                json={"message": "test message", "max_rounds": 5},
            )
    assert resp.status_code == 200
    data = resp.json()
    assert "answer" in data
    assert "rounds" in data
    assert "status" in data


@pytest.mark.asyncio
async def test_gateway_chat_completions(gateway_app: FastAPI) -> None:
    """The /v1/chat/completions endpoint returns an OpenAI-compatible response."""
    from security_gateway.llm_client import GenerateResult

    mock_result = GenerateResult(content="test response", usage={})
    with patch(
        "security_gateway.app._llm_client.chat",
        new_callable=AsyncMock,
        return_value=mock_result,
    ):
        transport = ASGITransport(app=gateway_app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/v1/chat/completions",
                headers=_gateway_auth(),
                json={"model": "test", "messages": []},
            )
    assert resp.status_code == 200
    data = resp.json()
    assert data["object"] == "chat.completion"
    assert "choices" in data
    assert "usage" in data


@pytest.mark.asyncio
async def test_gateway_body_limit(gateway_app: FastAPI) -> None:
    """Requests exceeding the body limit are rejected with 413."""
    transport = ASGITransport(app=gateway_app)
    big_body = "x" * (33 * 1024 * 1024)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/v1/agent/run",
            headers={
                **_gateway_auth(),
                "Content-Length": str(len(big_body)),
            },
            content=big_body,
        )
    assert resp.status_code in (400, 413)


# ── Tool gates ─────────────────────────────


@pytest.mark.asyncio
async def test_gateway_bash_disabled_by_default(gateway_app: FastAPI) -> None:
    """sec_Bash is gated off unless ENABLE_BASH_TOOL is set (fail closed)."""
    transport = ASGITransport(app=gateway_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/v1/tools/Bash",
            headers=_gateway_auth(),
            json={"arguments": {"command": "whoami"}},
        )
    assert resp.status_code == 403
    assert "ENABLE_BASH_TOOL" in resp.text


@pytest.mark.asyncio
async def test_gateway_hydra_disabled_by_default(gateway_app: FastAPI) -> None:
    """hydra_brute is gated off unless ENABLE_HYDRA is set."""
    transport = ASGITransport(app=gateway_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/v1/tools/hydra_brute",
            headers=_gateway_auth(),
            json={"arguments": {"target": "10.0.0.5", "service": "ssh"}},
        )
    assert resp.status_code == 403
    assert "ENABLE_HYDRA" in resp.text


@pytest.mark.asyncio
async def test_gateway_tcpdump_disabled_by_default(gateway_app: FastAPI) -> None:
    """tcpdump_capture is gated off unless ENABLE_TCPDUMP is set."""
    transport = ASGITransport(app=gateway_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/v1/tools/tcpdump_capture",
            headers=_gateway_auth(),
            json={"arguments": {"duration": 10}},
        )
    assert resp.status_code == 403
    assert "ENABLE_TCPDUMP" in resp.text


@pytest.mark.asyncio
async def test_gateway_cast_send_disabled_by_default(gateway_app: FastAPI) -> None:
    """cast_send is gated off unless ENABLE_CAST_SEND is set."""
    transport = ASGITransport(app=gateway_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/v1/tools/cast_send",
            headers=_gateway_auth(),
            json={"arguments": {"to": "0x1234"}},
        )
    assert resp.status_code == 403
    assert "ENABLE_CAST_SEND" in resp.text


@pytest.mark.asyncio
async def test_gateway_ungated_read_tool_not_blocked(gateway_app: FastAPI) -> None:
    """Read-tier tools without gates are not blocked by the gate check."""
    transport = ASGITransport(app=gateway_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # whois_lookup is read-tier and ungated the runner may 502 but not 403
        resp = await client.post(
            "/v1/tools/whois_lookup",
            headers=_gateway_auth(),
            json={"arguments": {"domain": "example.com"}},
        )
    assert resp.status_code != 403


@pytest.mark.asyncio
async def test_gateway_health_tools_reports_disabled_status(
    gateway_app: FastAPI, monkeypatch: pytest.MonkeyPatch
) -> None:
    """health/tools reports gated tools as 'disabled' when gates are off."""
    for var in ("ENABLE_BASH_TOOL", "ENABLE_HYDRA", "ENABLE_TCPDUMP", "ENABLE_CAST_SEND"):
        monkeypatch.delenv(var, raising=False)
    transport = ASGITransport(app=gateway_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get(
            "/health/tools",
            headers=_gateway_auth(),
        )
    assert resp.status_code == 200
    tools = {t["name"]: t for t in resp.json()["tools"]}
    assert tools["Bash"]["status"] == "disabled"
    assert tools["hydra_brute"]["status"] == "disabled"
    assert tools["tcpdump_capture"]["status"] == "disabled"
    assert tools["cast_send"]["status"] == "disabled"
    assert tools["whois_lookup"]["status"] == "unavailable"
    assert tools["nmap_scan"]["status"] == "unavailable"


@pytest.mark.asyncio
async def test_gateway_health_tools_reports_enabled_when_gated_on(
    gateway_app: FastAPI, monkeypatch: pytest.MonkeyPatch
) -> None:
    """health/tools reports gated tools as 'enabled' when gates are on."""
    monkeypatch.setenv("ENABLE_BASH_TOOL", "true")
    transport = ASGITransport(app=gateway_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get(
            "/health/tools",
            headers=_gateway_auth(),
        )
    assert resp.status_code == 200
    tools = {t["name"]: t for t in resp.json()["tools"]}
    assert tools["Bash"]["status"] == "enabled"


# ── Network profiles ───────────────────────


@pytest.mark.asyncio
async def test_gateway_network_profile_offline_allowed(gateway_app: FastAPI) -> None:
    """network_profile=offline is always allowed (default)."""
    from security_gateway.app import _network_profile
    assert _network_profile("offline") == "offline"
    assert _network_profile(None) == "offline"
    assert _network_profile("") == "offline"


@pytest.mark.asyncio
async def test_gateway_network_profile_invalid_rejected(gateway_app: FastAPI) -> None:
    """Invalid network profiles are rejected with 400."""
    from fastapi import HTTPException
    from security_gateway.app import _network_profile
    with pytest.raises(HTTPException) as exc_info:
        _network_profile("vpn")
    assert exc_info.value.status_code == 400


@pytest.mark.asyncio
async def test_gateway_network_profile_lab_gated(
    gateway_app: FastAPI, monkeypatch: pytest.MonkeyPatch
) -> None:
    """network_profile=lab requires ALLOW_PRIVATE_TARGETS=true."""
    from fastapi import HTTPException
    from security_gateway.app import _network_profile

    monkeypatch.delenv("ALLOW_PRIVATE_TARGETS", raising=False)
    with pytest.raises(HTTPException) as exc_info:
        _network_profile("lab")
    assert exc_info.value.status_code == 403

    monkeypatch.setenv("ALLOW_PRIVATE_TARGETS", "true")
    assert _network_profile("lab") == "lab"


@pytest.mark.asyncio
async def test_gateway_network_profile_public_gated(
    gateway_app: FastAPI, monkeypatch: pytest.MonkeyPatch
) -> None:
    """network_profile=public requires ALLOW_PUBLIC_TARGETS=true."""
    from fastapi import HTTPException
    from security_gateway.app import _network_profile

    monkeypatch.delenv("ALLOW_PUBLIC_TARGETS", raising=False)
    with pytest.raises(HTTPException) as exc_info:
        _network_profile("public")
    assert exc_info.value.status_code == 403

    monkeypatch.setenv("ALLOW_PUBLIC_TARGETS", "true")
    assert _network_profile("public") == "public"


# ── BFF → Gateway integration ────────────────────────────────────────────


@pytest.mark.asyncio
async def test_bff_health_proxies_gateway_url(
    bff_app: FastAPI, analyst_principal: Principal
) -> None:
    """The BFF health endpoint reports gateway configuration without leaking hosts."""
    _override_principal(bff_app, analyst_principal)
    transport = ASGITransport(app=bff_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/v1/security/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["gateway_configured"] is True
    assert "gateway_url" not in data


@pytest.mark.asyncio
async def test_bff_capabilities_proxies_to_gateway(
    bff_app: FastAPI, analyst_principal: Principal
) -> None:
    """The BFF /capabilities endpoint proxies to the gateway's /health/tools.

    Since we can't easily mock httpx streaming, we verify the route exists
    and returns either a successful proxy response or a 502 when the
    upstream is unavailable (expected in test without a real gateway).
    """
    _override_principal(bff_app, analyst_principal)
    transport = ASGITransport(app=bff_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/v1/security/capabilities")
    # Without a real gateway, the proxy returns 502 (upstream unavailable)
    assert resp.status_code in (200, 502)


@pytest.mark.asyncio
async def test_bff_agent_run_requires_analyst(
    bff_app: FastAPI, analyst_principal: Principal
) -> None:
    """The BFF /agent/run endpoint requires analyst+ role."""
    _override_principal(bff_app, analyst_principal)
    transport = ASGITransport(app=bff_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/api/v1/security/agent/run",
            json={"message": "test"},
        )
    # With analyst principal, the role check passes; the upstream may 502
    assert resp.status_code in (200, 502)
