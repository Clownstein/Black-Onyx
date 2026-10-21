"""Collector install guide URLs and asset detail helpers."""

from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace

from black_onyx.api import routes_assets
from black_onyx.api.routes_collectors import _remote_service_url
from black_onyx.auth.service import Principal, Role


def test_remote_service_url_prefers_remote_bind(monkeypatch) -> None:
    monkeypatch.delenv("INGEST_GATEWAY_URL", raising=False)
    monkeypatch.delenv("INGEST_GATEWAY_REMOTE_URL", raising=False)
    monkeypatch.setenv("INGEST_GATEWAY_REMOTE_BIND", "100.64.0.5")
    monkeypatch.setenv("INGEST_GATEWAY_REMOTE_PORT", "18091")
    assert _remote_service_url("INGEST_GATEWAY", host_port=18090, remote_port=18091) == "http://100.64.0.5:18091"


def test_remote_service_url_loopback_default(monkeypatch) -> None:
    monkeypatch.delenv("INGEST_GATEWAY_URL", raising=False)
    monkeypatch.delenv("INGEST_GATEWAY_REMOTE_URL", raising=False)
    monkeypatch.delenv("INGEST_GATEWAY_REMOTE_BIND", raising=False)
    monkeypatch.delenv("INGEST_GATEWAY_HOST_PORT", raising=False)
    assert _remote_service_url("INGEST_GATEWAY", host_port=18090, remote_port=18091) == "http://127.0.0.1:18090"


def test_asset_needles_includes_wazuh_agent() -> None:
    needles = routes_assets._asset_needles({
        "asset_id": "es-07",
        "hostname": "es-07",
        "tags": {"wazuh_agent_id": "003"},
    })
    assert "es-07" in needles
    assert "wazuh:003" in needles


def test_finding_matches_wazuh_alias() -> None:
    needles = routes_assets._asset_needles({"asset_id": "es-07", "tags": ["prod"]})
    assert routes_assets._finding_matches_asset(
        {"asset_id": "wazuh:003"},
        "es-07",
        needles | {"wazuh:003"},
    )


def test_detection_matches_nested_enrichment_asset_id() -> None:
    assert routes_assets._detection_matches_asset(
        {
            "hostname": "unrelated-host",
            "enrichment_data": {"asset_id": "wazuh:003"},
        },
        {"es-07", "wazuh:003"},
        "es-07",
    )


def test_asset_detail_falls_back_to_tip_row_when_registry_misses(monkeypatch) -> None:
    tip_asset = {
        "asset_id": "es-07",
        "hostname": "es-07",
        "ip_address": "10.0.0.7",
        "tags": ["wazuh:003"],
    }

    class AssetManager:
        @staticmethod
        def get_asset(asset_id):
            return tip_asset if asset_id == "es-07" else None

        @staticmethod
        def list_case_links(asset_id):
            return []

        @staticmethod
        def list_findings(limit):
            return []

    async def registry_miss(asset_id, user):
        return None

    async def no_incidents(asset_id, needles, user):
        return [], None

    monkeypatch.setattr(routes_assets, "_fetch_registry_asset", registry_miss)
    monkeypatch.setattr(routes_assets, "_fetch_related_incidents", no_incidents)
    monkeypatch.setattr(
        routes_assets,
        "_get_service",
        lambda: SimpleNamespace(
            asset_manager=AssetManager(),
            watchlist_manager=None,
            connector_manager=None,
            qdrant_store=None,
        ),
    )
    user = Principal("user-1", "analyst@example.com", "Analyst", Role.ANALYST)

    detail = asyncio.run(routes_assets.get_asset("es-07", user))

    assert detail["asset_id"] == "es-07"
    assert detail["sor"] == "tip_legacy_read"


def test_linux_collector_install_keeps_osquery_logs_group_readable() -> None:
    root = Path(__file__).resolve().parents[1]
    scripts = [
        root / "detection/collectors/installer/linux/install.sh",
        root / "detection/collectors/installer/linux/install-in-container.sh",
    ]
    for script in scripts:
        text = script.read_text(encoding="utf-8")
        assert "--logger_mode=0640" in text
        assert "--logger_mode=0644" not in text
        assert "--allow_unsafe" not in text
        assert "chmod 0750" in text
        assert "chmod 0640" in text and "osqueryd.results.log" in text


def test_wazuh_manager_address_order_and_request_host_fallback(monkeypatch) -> None:
    from black_onyx.api.routes_collectors import _wazuh_manager_address

    monkeypatch.setenv("WAZUH_MANAGER_ADDRESS", "wazuh.lab.internal")
    monkeypatch.setenv("INGEST_GATEWAY_REMOTE_BIND", "100.64.0.5")
    assert _wazuh_manager_address() == ("wazuh.lab.internal", True)
    monkeypatch.delenv("WAZUH_MANAGER_ADDRESS")
    assert _wazuh_manager_address() == ("100.64.0.5", True)
    monkeypatch.setenv("INGEST_GATEWAY_REMOTE_BIND", "127.0.0.1")
    monkeypatch.setenv("ASSET_REGISTRY_REMOTE_BIND", "127.0.0.1")
    monkeypatch.setenv("QDRANT_SECURITY__EXTERNAL_URL", "https://sec.example.org")
    assert _wazuh_manager_address() == ("sec.example.org", True)
    monkeypatch.setenv("QDRANT_SECURITY__EXTERNAL_URL", "http://127.0.0.1:8000")
    assert _wazuh_manager_address("blackonyx.lan") == ("blackonyx.lan", True)
    assert _wazuh_manager_address("127.0.0.1") == ("127.0.0.1", False)


def _guide_env(monkeypatch) -> None:
    monkeypatch.setenv("BLACK_ONYX_DETECTION_TENANT", "tenant-a")
    monkeypatch.setenv("WAZUH_MANAGER_ADDRESS", "100.64.0.5")
    monkeypatch.delenv("BLACK_ONYX_COLLECTOR_INGEST_KEY", raising=False)
    monkeypatch.setenv("API_KEYS", "ingest-key-1,ingest-key-2")
    monkeypatch.setenv("ASSET_REGISTRY_SERVICE_KEY", "registry-key")
    monkeypatch.setenv("WAZUH_REGISTRATION_PASSWORD", "Reg'Pass1-")


def test_wazuh_guide_commands_embed_quoted_real_values_when_revealed(monkeypatch) -> None:
    from black_onyx.api.routes_collectors import _guide_context, _structured_install_guides

    _guide_env(monkeypatch)
    guides = _structured_install_guides(_guide_context(reveal=True))
    wazuh = next(g for g in guides if g["id"] == "wazuh")
    commands = wazuh["commands"]
    assert "WAZUH_REGISTRATION_PASSWORD='Reg'\"'\"'Pass1-'" in commands["agent_linux_deb"]
    assert "WAZUH_REGISTRATION_PASSWORD='Reg''Pass1-'" in commands["agent_windows"]
    assert "WAZUH_MANAGER=100.64.0.5" in commands["agent_linux_rpm"]
    assert "signed-by=/usr/share/keyrings/wazuh.gpg" in commands["agent_linux_deb"]
    assert "ASSET_REGISTRY_SERVICE_KEY=registry-key" in commands["shipper_env"]
    osq = next(g for g in guides if g["id"] == "osquery_shipper")
    assert "BLACK_ONYX_COLLECTOR_INGEST_KEY=ingest-key-1" in osq["commands"]["linux"]


def test_guide_redacts_secrets_unless_revealed(monkeypatch) -> None:
    from black_onyx.api.routes_collectors import REDACTED, _guide_context, _structured_install_guides

    _guide_env(monkeypatch)
    ctx = _guide_context(reveal=False)
    text = repr(_structured_install_guides(ctx))
    for secret in ("ingest-key-1", "registry-key", "Reg"):
        assert secret not in text
    assert ctx["ingest_key"] == REDACTED and ctx["secrets_revealed"] is False


def test_guide_requires_tenant(monkeypatch) -> None:
    import pytest
    from fastapi import HTTPException

    from black_onyx.api.routes_collectors import _guide_context

    monkeypatch.delenv("BLACK_ONYX_DETECTION_TENANT", raising=False)
    with pytest.raises(HTTPException) as exc:
        _guide_context(reveal=False)
    assert exc.value.status_code == 503


def test_reveal_endpoint_is_admin_only_audited_and_not_cached(monkeypatch, tmp_path) -> None:
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from black_onyx.api import routes_collectors
    from black_onyx.auth.dependencies import current_principal

    _guide_env(monkeypatch)
    monkeypatch.setattr(routes_collectors, "_collectors_root", lambda: tmp_path)
    audits: list[tuple] = []

    class Auth:
        def audit(self, actor, action, *args, **kwargs):
            audits.append((actor.role, action))

    monkeypatch.setattr(routes_collectors, "get_auth_service", lambda: Auth())
    app = FastAPI()
    app.include_router(routes_collectors.collectors_router)
    principal = {"value": Principal("u1", "a@example.com", "A", Role.ANALYST)}
    app.dependency_overrides[current_principal] = lambda: principal["value"]
    client = TestClient(app)

    assert client.get("/api/v1/collectors/guide?reveal=true").status_code == 403
    plain = client.get("/api/v1/collectors/guide")
    assert plain.status_code == 200 and "ingest-key-1" not in plain.text
    assert plain.headers["cache-control"] == "no-store"

    principal["value"] = Principal("u2", "admin@example.com", "Admin", Role.ADMIN)
    revealed = client.get("/api/v1/collectors/guide?reveal=true")
    assert revealed.status_code == 200
    assert revealed.json()["ingest_key"] == "ingest-key-1"
    assert revealed.headers["cache-control"] == "no-store"
    assert audits == [(Role.ADMIN, "collectors.secrets.reveal")]


def test_related_incidents_queries_by_asset_aliases_and_reports_outage(monkeypatch) -> None:
    import httpx

    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["assets"] = request.url.params.get_list("asset")
        return httpx.Response(200, json={"items": [
            {"incident_id": "inc-1", "title": "t", "assets": ["wazuh:003"], "severity": "high"},
            {"incident_id": "inc-2", "title": "other", "assets": ["unrelated"]},
        ]})

    real_client = httpx.AsyncClient
    monkeypatch.setattr(
        routes_assets.httpx, "AsyncClient",
        lambda **kw: real_client(transport=httpx.MockTransport(handler), **kw),
    )
    monkeypatch.setattr(routes_assets, "_registry_headers", lambda user: {})
    user = Principal("u1", "a@example.com", "A", Role.ANALYST)
    rows, error = asyncio.run(routes_assets._fetch_related_incidents("es-07", {"wazuh:003"}, user))
    assert sorted(seen["assets"]) == ["es-07", "wazuh:003"]
    assert [r["incident_id"] for r in rows] == ["inc-1"]
    assert error is None

    def down(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    monkeypatch.setattr(
        routes_assets.httpx, "AsyncClient",
        lambda **kw: real_client(transport=httpx.MockTransport(down), **kw),
    )
    rows, error = asyncio.run(routes_assets._fetch_related_incidents("es-07", set(), user))
    assert rows == [] and error == "incident-api unreachable"
