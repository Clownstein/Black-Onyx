"""Registered challenge adapters never execute submitted content."""
from __future__ import annotations

import json
import socket
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

GATEWAY_ROOT = Path(__file__).resolve().parents[1] / "services" / "security-gateway"
if str(GATEWAY_ROOT) not in sys.path:
    sys.path.insert(0, str(GATEWAY_ROOT))

from security_gateway import challenge_adapter as adapter
from security_gateway.execution_spec import build_execution


@pytest.mark.asyncio
async def test_reference_challenge_is_persisted_per_actor(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("SECURITY_CHALLENGE_DB", str(tmp_path / "challenges.sqlite3"))
    assert adapter.ready()
    assert (await adapter.status("analyst-a", "reference-basic"))["solved"] is False
    rejected = await adapter.submit("analyst-a", "reference-basic", "not the flag")
    assert rejected["accepted"] is False
    accepted = await adapter.submit("analyst-a", "reference-basic", "flag{black_onyx_reference}")
    assert accepted["accepted"] is True
    assert (await adapter.status("analyst-a", "reference-basic"))["solved"] is True
    assert (await adapter.status("analyst-b", "reference-basic"))["solved"] is False


@pytest.mark.asyncio
async def test_registered_provider_uses_pinned_ip_and_rejects_redirects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SECURITY_CHALLENGE_PROVIDERS_JSON", json.dumps({"owned-lab": {
        "status_url": "http://challenge.security-lab.svc/status",
        "submit_url": "http://challenge.security-lab.svc/submit",
        "allowed_ips": ["10.88.0.10"],
    }}))
    records = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("10.88.0.10", 80))]
    monkeypatch.setattr(adapter.socket, "getaddrinfo", lambda *_args: records)
    calls: list[tuple[str, str, dict]] = []

    class FakeResponse:
        status_code = 200
        is_redirect = False
        headers: dict[str, str] = {}

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def aiter_bytes(self):
            yield b'{"solved":false}'

    class FakeClient:
        def __init__(self, **kwargs):
            assert kwargs["trust_env"] is False
            assert kwargs["follow_redirects"] is False

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        def stream(self, method, url, **kwargs):
            calls.append((method, url, kwargs))
            return FakeResponse()

    monkeypatch.setattr(adapter.httpx, "AsyncClient", FakeClient)
    assert (await adapter.status("analyst", "owned-lab"))["solved"] is False
    method, url, kwargs = calls[0]
    assert method == "GET"
    assert url == "http://10.88.0.10:80/status"
    assert kwargs["headers"]["Host"] == "challenge.security-lab.svc"

    class RedirectResponse(FakeResponse):
        status_code = 302
        is_redirect = True

    class RedirectClient(FakeClient):
        def stream(self, method, url, **kwargs):
            calls.append((method, url, kwargs))
            return RedirectResponse()

    monkeypatch.setattr(adapter.httpx, "AsyncClient", RedirectClient)
    with pytest.raises(adapter.ChallengeUnavailable, match="unsuccessful response"):
        await adapter.status("analyst", "owned-lab")
    assert len(calls) == 2  # one provider request; redirects are never followed


def test_challenge_solution_is_bounded_text_data_and_not_a_path() -> None:
    assert adapter.validate_solution('{"answer":"flag{ok}"}')
    assert adapter.validate_solution("#!/bin/sh\nprintf bad")  # remains inert text data
    with pytest.raises(ValueError, match="16 KiB"):
        adapter.validate_solution("x" * (16 * 1024 + 1))
    with pytest.raises(ValueError, match="UTF-8"):
        adapter.validate_solution("bad\x00text")
    with pytest.raises(KeyError):
        import asyncio
        asyncio.run(adapter.status("operator", "unregistered-id"))
    assert build_execution("submit_solution", {
        "challenge_id": "reference-basic", "solution": "some text",
    })["argv"] == ["__trusted_adapter__", "submit_solution"]
    with pytest.raises(ValueError, match="recipient"):
        build_execution("cast_send", {"to": "0x1"})


def test_provider_registry_requires_fixed_endpoints_and_ip_pins(monkeypatch: pytest.MonkeyPatch) -> None:
    provider = {
        "status_url": "https://challenge.example/api/status",
        "submit_url": "https://challenge.example/api/submit",
        "allowed_ips": ["93.184.216.34"],
    }
    monkeypatch.setenv("SECURITY_CHALLENGE_PROVIDERS_JSON", json.dumps({"owned-lab": provider}))
    registered = adapter._registry()["owned-lab"]
    records = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 443))]
    with patch("security_gateway.challenge_adapter.socket.getaddrinfo", return_value=records):
        assert adapter._resolve_pinned("challenge.example", 443, registered["allowed_ips"]) == ["93.184.216.34"]
    foreign = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("1.1.1.1", 443))]
    with patch("security_gateway.challenge_adapter.socket.getaddrinfo", return_value=foreign):
        with pytest.raises(adapter.ChallengeUnavailable, match="registered addresses"):
            adapter._resolve_pinned("challenge.example", 443, registered["allowed_ips"])


@pytest.mark.parametrize("provider", [
    {"status_url": "http://challenge.example/status", "submit_url": "http://challenge.example/submit", "allowed_ips": ["93.184.216.34"]},
    {"status_url": "http://169.254.169.254/latest/meta-data", "submit_url": "http://169.254.169.254/submit", "allowed_ips": ["169.254.169.254"]},
    {"status_url": "https://challenge.example/status?next=http://localhost", "submit_url": "https://challenge.example/submit", "allowed_ips": ["93.184.216.34"]},
    {"status_url": "https://challenge.example/status", "submit_url": "https://other.example/submit", "allowed_ips": ["93.184.216.34"]},
])
def test_provider_registry_rejects_unsafe_endpoints(monkeypatch: pytest.MonkeyPatch, provider: dict) -> None:
    monkeypatch.setenv("SECURITY_CHALLENGE_PROVIDERS_JSON", json.dumps({"owned-lab": provider}))
    with pytest.raises(ValueError):
        adapter._registry()
