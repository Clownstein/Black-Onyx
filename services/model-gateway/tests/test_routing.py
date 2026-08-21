from __future__ import annotations

from typing import Any

import httpx
import pytest
from model_gateway import main as main_mod
from model_gateway.main import app
from model_gateway.routing import select_alias_for_request, tenant_bucket
from fastapi.testclient import TestClient


def test_canary_split_is_deterministic_and_respects_percent() -> None:
    tenants = [f"tenant-{i}" for i in range(200)]
    canary = [
        t for t in tenants if select_alias_for_request(None, t, canary_percent=25) == "canary"
    ]
    champion = [
        t for t in tenants if select_alias_for_request(None, t, canary_percent=25) == "champion"
    ]
    assert len(canary) + len(champion) == len(tenants)
    assert 30 <= len(canary) <= 70
    for t in tenants:
        assert select_alias_for_request(None, t, canary_percent=25) == select_alias_for_request(
            None, t, canary_percent=25
        )
    assert select_alias_for_request("shadow", "tenant-1", canary_percent=100) == "shadow"
    assert select_alias_for_request(None, "x", canary_percent=0) == "champion"
    assert 0 <= tenant_bucket("tenant-acme") < 100


def test_predict_routes_to_model_url(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, dict[str, Any]]] = []

    async def fake_post(url: str, payload: dict[str, Any], timeout: float) -> dict[str, Any]:
        calls.append((url, payload))
        return {"score": 0.9, "upstream": url}

    monkeypatch.setattr(main_mod, "_post_predict", fake_post)
    monkeypatch.setattr(main_mod.settings, "log_model_url", "http://log-model:8090")
    monkeypatch.setattr(main_mod.settings, "canary_percent", 0)

    client = TestClient(app)
    response = client.post(
        "/v1/predict",
        json={
            "model_name": "log-model",
            "tenant_id": "tenant-acme",
            "alias": "champion",
            "features": {"x": 1},
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["routed_alias"] == "champion"
    assert calls
    assert calls[0][0].startswith("http://log-model:8090/v1/predict")


def test_shadow_does_not_fail_request(monkeypatch: pytest.MonkeyPatch) -> None:
    primary_calls = 0

    async def fake_post(url: str, payload: dict[str, Any], timeout: float) -> dict[str, Any]:
        nonlocal primary_calls
        if "alias=shadow" in url:
            raise httpx.ConnectError("shadow down")
        primary_calls += 1
        return {"score": 0.5}

    monkeypatch.setattr(main_mod, "_post_predict", fake_post)
    monkeypatch.setattr(main_mod.settings, "log_model_url", "http://log-model:8090")

    client = TestClient(app)
    response = client.post(
        "/v1/predict",
        json={
            "model_name": "log-model",
            "tenant_id": "tenant-acme",
            "alias": "shadow",
            "batch": [],
        },
    )
    assert response.status_code == 200
    assert response.json()["routed_alias"] == "champion"
    assert primary_calls >= 1


def test_predict_merges_items_and_model_request(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[dict[str, Any]] = []

    async def fake_post(url: str, payload: dict[str, Any], timeout: float) -> dict[str, Any]:
        calls.append(payload)
        return {"score": 0.42, "model_version": "0.1.0"}

    monkeypatch.setattr(main_mod, "_post_predict", fake_post)
    monkeypatch.setattr(main_mod.settings, "log_model_url", "http://log-model:8090")
    monkeypatch.setattr(main_mod.settings, "canary_percent", 0)

    client = TestClient(app)
    response = client.post(
        "/v1/predict",
        json={
            "model_name": "log-model",
            "tenant_id": "tenant-acme",
            "request_id": "req-9",
            "feature_version": "1.0",
            "features": {"asset_id": "host-1", "template_ids": ["tpl-a"]},
            "items": [{"sequence_id": "seq-1", "events": [{"template_id": "tpl-a"}]}],
            "model_request": {
                "request_id": "req-9",
                "tenant_id": "tenant-acme",
                "model_name": "log-model",
                "feature_version": "1.0",
                "items": [{"sequence_id": "seq-1", "events": [{"template_id": "tpl-a"}]}],
            },
        },
    )
    assert response.status_code == 200
    assert calls
    upstream = calls[0]
    assert upstream["request_id"] == "req-9"
    assert upstream["tenant_id"] == "tenant-acme"
    assert upstream["asset_id"] == "host-1"
    assert upstream["items"][0]["sequence_id"] == "seq-1"


def test_predict_forwards_network_model_request(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[dict[str, Any]] = []

    async def fake_post(url: str, payload: dict[str, Any], timeout: float) -> dict[str, Any]:
        calls.append(payload)
        return {"risk_score": 0.8}

    monkeypatch.setattr(main_mod, "_post_predict", fake_post)
    monkeypatch.setattr(main_mod.settings, "network_model_url", "http://network-model:8101")
    monkeypatch.setattr(main_mod.settings, "canary_percent", 0)

    client = TestClient(app)
    response = client.post(
        "/v1/predict",
        json={
            "model_name": "network-model",
            "tenant_id": "tenant-acme",
            "features": {"aggregates": {"distinct_peers": 2}},
            "model_request": {
                "flows": [{"peer_hash": "abc"}],
                "detections": [{"type": "new_external_peer"}],
                "aggregates": {"distinct_peers": 2},
            },
        },
    )
    assert response.status_code == 200
    assert calls[0]["flows"][0]["peer_hash"] == "abc"
    assert calls[0]["detections"][0]["type"] == "new_external_peer"


@pytest.mark.parametrize(
    ("model_name", "url_attr", "url"),
    [
        ("log-model", "log_model_url", "http://log-model:8090"),
        ("code-model", "code_model_url", "http://code-model:8103"),
        ("network-model", "network_model_url", "http://network-model:8101"),
        ("metrics-model", "metrics_model_url", "http://metrics-model:8102"),
    ],
)
def test_canary_routes_all_four_models(
    monkeypatch: pytest.MonkeyPatch,
    model_name: str,
    url_attr: str,
    url: str,
) -> None:
    calls: list[str] = []

    async def fake_post(upstream: str, payload: dict[str, Any], timeout: float) -> dict[str, Any]:
        calls.append(upstream)
        return {"risk_score": 0.5, "calibrated_score": 0.5}

    monkeypatch.setattr(main_mod, "_post_predict", fake_post)
    monkeypatch.setattr(main_mod.settings, url_attr, url)
    monkeypatch.setattr(main_mod.settings, "canary_percent", 100)

    client = TestClient(app)
    response = client.post(
        "/v1/predict",
        json={
            "model_name": model_name,
            "tenant_id": "tenant-canary-all",
            "features": {},
            "model_request": {},
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["routed_alias"] == "canary"
    assert calls
    assert calls[0].startswith(f"{url}/v1/predict")
    assert "alias=canary" in calls[0]
