from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from integration_hub.playbooks import execute_playbook, load_playbook, normalize_playbook_id
from integration_hub import adapters, config, wazuh_active_response


def test_normalize_playbook_id() -> None:
    assert normalize_playbook_id("block-ip-pfsense") == "packs/v1/block-ip-pfsense"
    assert normalize_playbook_id("packs/v1/notify-webhook.yaml") == "packs/v1/notify-webhook"


def test_load_pack_yaml_from_repo() -> None:
    root = Path(__file__).resolve().parents[3] / "playbooks"
    pb = load_playbook("packs/v1/block-ip-pfsense", root=root)
    assert pb["id"] == "block-ip-pfsense"
    assert any(s.get("action") == "pfsense.block_ip" for s in pb["steps"])


def test_execute_notify_webhook_dry_run() -> None:
    result = execute_playbook(
        "packs/v1/notify-webhook",
        {
            "webhook_url": "https://hooks.example.test/x",
            "incident": {"incident_id": "inc-1", "title": "t", "severity": "low"},
        },
        dry_run=True,
    )
    assert result["executed"] is True
    deliver = next(s for s in result["steps"] if s["action"] == "http.post")
    assert deliver["result"]["dry_run"] is True
    assert deliver["result"]["url"] == "https://hooks.example.test/x"


def test_live_response_adapters_fail_when_vendor_is_unconfigured(monkeypatch) -> None:
    monkeypatch.setattr(config.settings, "pfsense_api_url", "")
    monkeypatch.setattr(config.settings, "edr_api_url", "")

    blocked = adapters.pfsense_block_ip({"ip": "203.0.113.10"}, dry_run=False)
    isolated = adapters.edr_isolate_host({"asset_id": "host-1"}, dry_run=False)

    assert blocked["ok"] is False
    assert blocked["queued_external"] is False
    assert isolated["ok"] is False
    assert isolated["queued_external"] is False


def _wazuh_settings(monkeypatch) -> None:
    monkeypatch.setattr(config.settings, "edr_provider", "wazuh")
    monkeypatch.setattr(config.settings, "edr_api_url", "https://generic-edr.example.test")
    monkeypatch.setattr(config.settings, "wazuh_api_url", "https://wazuh.corp.local:55000")
    monkeypatch.setattr(config.settings, "wazuh_api_user", "blackonyx")
    monkeypatch.setattr(config.settings, "wazuh_api_password", "secret")
    monkeypatch.setattr(config.settings, "wazuh_isolation_allow", "10.0.0.5, 10.0.9.0/24")


def _mock_wazuh(monkeypatch, *, platform: str = "ubuntu", affected: int = 1) -> list[httpx.Request]:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path == "/security/user/authenticate":
            return httpx.Response(200, json={"data": {"token": "jwt-token"}})
        if request.url.path == "/agents":
            return httpx.Response(200, json={"data": {"affected_items": [{"id": "003", "os": {"platform": platform}}]}})
        if request.url.path == "/active-response":
            return httpx.Response(200, json={"data": {
                "affected_items": ["003"] if affected else [], "total_affected_items": affected, "failed_items": [],
            }})
        return httpx.Response(404)

    real_client = httpx.Client
    monkeypatch.setattr(
        wazuh_active_response.httpx, "Client",
        lambda **kwargs: real_client(transport=httpx.MockTransport(handler), **kwargs),
    )
    return requests


def test_wazuh_isolation_dry_run_makes_no_http_calls(monkeypatch) -> None:
    _wazuh_settings(monkeypatch)
    requests = _mock_wazuh(monkeypatch)
    result = adapters.edr_isolate_host({"asset_id": "wazuh:003", "ttl_minutes": 30}, dry_run=True)
    assert result == {"ok": True, "dry_run": True, "would_send": {
        "action": "isolate_host", "asset_id": "wazuh:003", "reason": "incident response", "ttl_minutes": 30,
    }}
    assert requests == []


def test_wazuh_isolation_rejects_non_wazuh_asset(monkeypatch) -> None:
    _wazuh_settings(monkeypatch)
    with pytest.raises(ValueError, match="wazuh:<agent_id>"):
        adapters.edr_isolate_host({"asset_id": "host-1"}, dry_run=True)


def test_wazuh_isolation_live_dispatches_active_response(monkeypatch) -> None:
    _wazuh_settings(monkeypatch)
    requests = _mock_wazuh(monkeypatch)
    result = adapters.edr_isolate_host({"asset_id": "wazuh:003", "ttl_minutes": 45, "reason": "c2"}, dry_run=False)
    assert result["ok"] is True
    assert result["agent_id"] == "003"
    assert result["command"] == "!black-onyx-isolate"
    paths = [r.url.path for r in requests]
    assert paths == ["/security/user/authenticate", "/agents", "/active-response"]
    assert all(r.url.host == "wazuh.corp.local" for r in requests)
    ar = requests[-1]
    assert ar.method == "PUT"
    assert ar.url.params["agents_list"] == "003"
    assert ar.headers["authorization"] == "Bearer jwt-token"
    assert json.loads(ar.content) == {"command": "!black-onyx-isolate", "arguments": [
        "ttl_minutes=45", "reason=c2", "allow=10.0.0.5", "allow=10.0.9.0/24",
    ]}


def test_wazuh_isolation_arguments_cannot_smuggle_allow_entries() -> None:
    args = wazuh_active_response.isolation_arguments(
        {"ttl_minutes": 30, "reason": 'c2,allow=0.0.0.0/0"]\nx'}, "10.0.0.5",
    )
    assert args == ["ttl_minutes=30", "reason=c2 allow 0.0.0.0/0 x", "allow=10.0.0.5"]
    assert all("," not in arg for arg in args)
    with pytest.raises(ValueError, match="not an IP address or CIDR"):
        wazuh_active_response.isolation_arguments({"ttl_minutes": 30}, "jump.corp.local")


def test_wazuh_isolation_selects_windows_command_and_reports_failure(monkeypatch) -> None:
    _wazuh_settings(monkeypatch)
    requests = _mock_wazuh(monkeypatch, platform="windows", affected=0)
    result = adapters.edr_isolate_host({"asset_id": "wazuh:003"}, dry_run=False)
    assert result["ok"] is False
    assert result["error"] == "wazuh_active_response_failed"
    assert json.loads(requests[-1].content)["command"] == "!black-onyx-isolate.cmd"


def test_wazuh_isolation_unconfigured_does_not_fall_back(monkeypatch) -> None:
    _wazuh_settings(monkeypatch)
    monkeypatch.setattr(config.settings, "wazuh_api_url", "")
    requests = _mock_wazuh(monkeypatch)
    result = adapters.edr_isolate_host({"asset_id": "wazuh:003"}, dry_run=False)
    assert result["ok"] is False
    assert result["error"] == "unconfigured"
    assert requests == []


def test_webhook_rejects_private_destination_even_in_dry_run() -> None:
    try:
        adapters.http_post({"webhook_url": "https://127.0.0.1/hook"}, dry_run=True)
    except ValueError as exc:
        assert "non-public" in str(exc)
    else:
        raise AssertionError("private webhook destination was accepted")
