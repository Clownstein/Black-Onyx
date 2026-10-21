"""Golden contract checks for model-gateway champion vs canary/shadow routing."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[3]
GW = ROOT / "services" / "model-gateway"
if str(GW) not in sys.path:
    sys.path.insert(0, str(GW))

import pytest
from fastapi.testclient import TestClient

from model_gateway import main as main_mod  # noqa: E402
from model_gateway.main import app  # noqa: E402


GOLDEN_FEATURES = {
    "asset_id": "host-golden-01",
    "template_ids": ["tpl-login-fail", "tpl-sudo"],
}


def _contract_score(alias: str, score: float) -> dict[str, Any]:
    return {
        "raw_score": score,
        "calibrated_score": score,
        "contributors": [
            {"feature": "template_ids", "weight": 0.6},
            {"feature": "asset_id", "weight": 0.4},
        ],
        "model_version": f"golden-{alias}",
    }


async def _confirmed_aliases(_model: str, _tenant: str) -> dict[str, Any]:
    return {
        alias: {
            "version": f"golden-{alias}",
            "signature": f"signed-golden-{alias}",
            "generation": 1,
            "confirmed": True,
        }
        for alias in ("champion", "canary", "shadow")
    }


@pytest.mark.parametrize("model_name", ["log-model", "network-model", "metrics-model", "code-model"])
def test_champion_and_canary_return_contract_fields(monkeypatch: pytest.MonkeyPatch, model_name: str) -> None:
    async def fake_post(url: str, payload: dict[str, Any], timeout: float) -> dict[str, Any]:
        alias = "canary" if "alias=canary" in url else "champion"
        score = 0.81 if alias == "canary" else 0.42
        return _contract_score(alias, score)

    monkeypatch.setattr(main_mod, "_post_predict", fake_post)
    monkeypatch.setattr(main_mod, "serving_aliases", _confirmed_aliases)
    monkeypatch.setattr(main_mod.settings, "api_key", "golden-model-key")
    monkeypatch.setattr(main_mod.settings, "canary_percent", 0)
    for attr in ("log_model_url", "network_model_url", "metrics_model_url", "code_model_url"):
        monkeypatch.setattr(main_mod.settings, attr, "http://upstream:8090")

    client = TestClient(app, headers={"X-API-Key": "golden-model-key"})
    for alias, expected_score in (("champion", 0.42), ("canary", 0.81)):
        response = client.post(
            "/v1/predict",
            json={
                "model_name": model_name,
                "tenant_id": "tenant-golden",
                "alias": alias,
                "features": GOLDEN_FEATURES,
            },
        )
        assert response.status_code == 200
        body = response.json()
        assert body["routed_alias"] == alias
        assert body["raw_score"] == expected_score
        assert body["calibrated_score"] == expected_score
        assert isinstance(body["contributors"], list) and body["contributors"]
        assert body["model_name"] == model_name


def test_shadow_probe_keeps_champion_contract(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    async def fake_post(url: str, payload: dict[str, Any], timeout: float) -> dict[str, Any]:
        calls.append(url)
        if "alias=shadow" in url:
            return _contract_score("shadow", 0.99)
        return _contract_score("champion", 0.55)

    monkeypatch.setattr(main_mod, "_post_predict", fake_post)
    monkeypatch.setattr(main_mod, "serving_aliases", _confirmed_aliases)
    monkeypatch.setattr(main_mod.settings, "api_key", "golden-model-key")
    monkeypatch.setattr(main_mod.settings, "log_model_url", "http://log-model:8090")

    client = TestClient(app, headers={"X-API-Key": "golden-model-key"})
    response = client.post(
        "/v1/predict",
        json={
            "model_name": "log-model",
            "tenant_id": "tenant-golden",
            "alias": "shadow",
            "features": GOLDEN_FEATURES,
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["routed_alias"] == "champion"
    assert body["raw_score"] == 0.55
    assert any("alias=shadow" in url for url in calls)
    assert any("alias=champion" in url for url in calls)
