"""Unit tests for absorption overlap paths (promote, TI sync, asset migrate)."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from black_onyx.auth.service import Principal, Role
from black_onyx.threat_intel_sync import _normalize_type, sync_indicators_to_threat_intel


@pytest.fixture(autouse=True)
def _auth_secret(monkeypatch):
    monkeypatch.setenv("BLACK_ONYX_AUTH_SECRET", "test-secret-absorption-overlap")


def test_normalize_ioc_types():
    assert _normalize_type("IP") == "ipv4"
    assert _normalize_type("hostname") == "domain"
    assert _normalize_type("sha256") == "hash"
    assert _normalize_type("unknown-xyz") == "unknown-xyz"


@pytest.mark.asyncio
async def test_sync_indicators_skips_empty():
    result = await sync_indicators_to_threat_intel([])
    assert result["status"] == "skipped"
    assert result["upserted"] == 0


@pytest.mark.asyncio
async def test_sync_indicators_posts_upsert(monkeypatch):
    monkeypatch.setenv("BLACK_ONYX_THREAT_INTEL_URL", "http://ti.test:8098")
    monkeypatch.setenv("THREAT_INTEL_SERVICE_KEY", "svc-key")

    class FakeResp:
        status_code = 200
        content = b'{"upserted": 1}'
        text = '{"upserted": 1}'

        def json(self):
            return {"upserted": 1}

    class FakeClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def post(self, url, json=None, headers=None):
            assert url.endswith("/api/v1/indicators/upsert")
            assert headers.get("X-Service-Key") == "svc-key"
            assert json["indicators"][0]["observable_value"] == "1.2.3.4"
            assert json["indicators"][0]["observable_type"] == "ipv4"
            return FakeResp()

    with patch("black_onyx.threat_intel_sync.httpx.AsyncClient", FakeClient):
        result = await sync_indicators_to_threat_intel(
            [{"ioc_type": "ip", "ioc_value": "1.2.3.4", "confidence": 90}]
        )
    assert result["status"] == "ok"
    assert result["upserted"] == 1


def test_promote_detection_incident_links_external_id():
    from black_onyx.api import routes_analytics

    created = SimpleNamespace(
        case_id="case-1",
        title="Detection incident inc-99",
        external_incident_id="inc-99",
        __dict__={"case_id": "case-1", "external_incident_id": "inc-99"},
    )
    case_manager = MagicMock()
    case_manager.get_case_by_external_incident.return_value = None
    case_manager.create_case.return_value = created
    case_manager.add_timeline_event.return_value = None

    service = SimpleNamespace(case_manager=case_manager)
    app = FastAPI()
    app.include_router(routes_analytics.analytics_router)

    @app.middleware("http")
    async def inject_analyst(request, call_next):
        request.state.principal = Principal(
            user_id="analyst-1",
            email="analyst@example.com",
            display_name="Analyst",
            role=Role.ANALYST,
        )
        return await call_next(request)

    with patch.object(routes_analytics, "_get_service", return_value=service):
        client = TestClient(app)
        resp = client.post(
            "/api/v1/detection-incidents/promote",
            json={"incident_id": "inc-99", "title": "Promoted"},
        )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "ok"
    assert body["external_incident_id"] == "inc-99"
    case_manager.create_case.assert_called_once()
    kwargs = case_manager.create_case.call_args.kwargs
    assert kwargs["external_incident_id"] == "inc-99"
    assert "detection-spine" in kwargs["tags"]


def test_promote_detection_incident_is_idempotent():
    from black_onyx.api import routes_analytics

    existing = SimpleNamespace(
        case_id="case-existing",
        __dict__={"case_id": "case-existing", "external_incident_id": "inc-1"},
    )
    case_manager = MagicMock()
    case_manager.get_case_by_external_incident.return_value = existing
    service = SimpleNamespace(case_manager=case_manager)
    app = FastAPI()
    app.include_router(routes_analytics.analytics_router)

    @app.middleware("http")
    async def inject_analyst(request, call_next):
        request.state.principal = Principal(
            user_id="analyst-1",
            email="analyst@example.com",
            display_name="Analyst",
            role=Role.ANALYST,
        )
        return await call_next(request)

    with patch.object(routes_analytics, "_get_service", return_value=service):
        client = TestClient(app)
        resp = client.post(
            "/api/v1/detection-incidents/promote",
            json={"incident_id": "inc-1"},
        )
    assert resp.status_code == 200
    assert resp.json()["case_id"] == "case-existing"
    case_manager.create_case.assert_not_called()


@pytest.mark.asyncio
async def test_migrate_assets_to_registry_counts():
    from black_onyx.api import routes_assets

    tip_rows = [
        {"hostname": "web-01", "asset_id": "web-01", "asset_type": "host"},
        {"hostname": "", "asset_id": "", "asset_type": "host"},
    ]
    asset_manager = MagicMock()
    asset_manager.list_assets.return_value = tip_rows
    service = SimpleNamespace(asset_manager=asset_manager)
    user = Principal(
        user_id="a1",
        email="a@b.c",
        display_name="A",
        role=Role.ANALYST,
    )

    with (
        patch.object(routes_assets, "_get_service", return_value=service),
        patch.object(routes_assets, "_upsert_registry_asset", new=AsyncMock(return_value=True)) as upsert,
    ):
        result = await routes_assets.migrate_assets_to_registry(user)
    assert result["status"] == "ok"
    assert result["migrated"] == 1
    assert result["skipped"] == 1
    assert result["tip_total"] == 2
    assert upsert.await_count == 1


@pytest.mark.asyncio
async def test_create_asset_fail_closed_when_registry_down():
    from fastapi import HTTPException

    from black_onyx.api import routes_assets
    from black_onyx.api.routes_assets import AssetCreateRequest

    user = Principal(
        user_id="a1",
        email="a@b.c",
        display_name="A",
        role=Role.ANALYST,
    )
    tip = MagicMock()
    with (
        patch.object(routes_assets, "_get_service", return_value=SimpleNamespace(asset_manager=tip)),
        patch.object(routes_assets, "_upsert_registry_asset", new=AsyncMock(return_value=False)),
    ):
        with pytest.raises(HTTPException) as exc:
            await routes_assets.create_asset(
                AssetCreateRequest(hostname="web-01", asset_type="host"),
                user,
            )
    assert exc.value.status_code == 502
    tip.create_asset.assert_not_called()
