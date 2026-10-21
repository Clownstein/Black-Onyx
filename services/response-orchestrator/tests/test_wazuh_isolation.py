import json

import httpx
import pytest
from response_orchestrator import adapters, wazuh_active_response
from response_orchestrator.config import settings


@pytest.fixture
def wazuh_settings(monkeypatch):
    monkeypatch.setattr(settings, "edr_provider", "wazuh")
    monkeypatch.setattr(settings, "edr_api_url", "https://generic-edr.example.test")
    monkeypatch.setattr(settings, "wazuh_api_url", "https://wazuh.corp.local:55000")
    monkeypatch.setattr(settings, "wazuh_api_user", "blackonyx")
    monkeypatch.setattr(settings, "wazuh_api_password", "secret")
    monkeypatch.setattr(settings, "wazuh_isolation_allow", "")


def _mock_wazuh(monkeypatch, platform: str = "ubuntu") -> list[httpx.Request]:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path == "/security/user/authenticate":
            return httpx.Response(200, json={"data": {"token": "jwt-token"}})
        if request.url.path == "/agents":
            return httpx.Response(200, json={"data": {"affected_items": [{"id": "012", "os": {"platform": platform}}]}})
        if request.url.path == "/active-response":
            return httpx.Response(200, json={"data": {
                "affected_items": ["012"], "total_affected_items": 1, "failed_items": [],
            }})
        return httpx.Response(404)

    real_client = httpx.Client
    monkeypatch.setattr(
        wazuh_active_response.httpx, "Client",
        lambda **kwargs: real_client(transport=httpx.MockTransport(handler), **kwargs),
    )
    return requests


def test_dry_run_returns_action_without_calling_wazuh(wazuh_settings, monkeypatch) -> None:
    requests = _mock_wazuh(monkeypatch)
    result = adapters.isolate_host({"asset_id": "wazuh:012"}, dry_run=True)
    assert result["dry_run"] is True
    assert result["would_send"]["asset_id"] == "wazuh:012"
    assert requests == []


def test_live_uses_active_response_not_generic_edr(wazuh_settings, monkeypatch) -> None:
    requests = _mock_wazuh(monkeypatch, platform="windows")
    result = adapters.isolate_host({"asset_id": "wazuh:012", "ttl_minutes": 60}, dry_run=False)
    assert result["ok"] is True
    assert result["agent_id"] == "012"
    assert [r.url.path for r in requests] == ["/security/user/authenticate", "/agents", "/active-response"]
    assert not any(r.url.path == "/api/v1/hosts/isolate" for r in requests)
    body = json.loads(requests[-1].content)
    assert body["command"] == "!black-onyx-isolate.cmd"
    assert body["arguments"][0] == "ttl_minutes=60"


def test_rejects_non_wazuh_asset(wazuh_settings) -> None:
    with pytest.raises(ValueError, match="wazuh:<agent_id>"):
        adapters.isolate_host({"asset_id": "host-1"}, dry_run=True)


def test_isolation_arguments_sanitize_reason_and_validate_allow() -> None:
    args = wazuh_active_response.isolation_arguments(
        {"ttl_minutes": 45, "reason": "beacon,allow=0.0.0.0/0"}, "fd00::5, 10.0.9.0/24",
    )
    assert args == ["ttl_minutes=45", "reason=beacon allow 0.0.0.0/0", "allow=fd00::5", "allow=10.0.9.0/24"]
    with pytest.raises(ValueError, match="not an IP address or CIDR"):
        wazuh_active_response.isolation_arguments({"ttl_minutes": 45}, "10.0.0.0/33")


def test_unknown_provider_is_rejected(monkeypatch) -> None:
    monkeypatch.setattr(settings, "edr_provider", "carbonblack")
    with pytest.raises(ValueError, match="unsupported EDR provider"):
        adapters.isolate_host({"asset_id": "host-1"}, dry_run=True)
