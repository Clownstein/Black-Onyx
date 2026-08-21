from __future__ import annotations

import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
for mod in list(sys.modules):
    if mod == "app" or mod.startswith("app."):
        del sys.modules[mod]

from inference_worker.config import settings  # noqa: E402
from inference_worker.main import app  # noqa: E402


@pytest.fixture()
def client() -> TestClient:
    return TestClient(app)


def test_score_once_rejects_missing_or_wrong_api_key(client: TestClient) -> None:
    saved = settings.api_key
    settings.api_key = "secret-key"
    try:
        missing = client.post(
            "/v1/score-once",
            json={"model_name": "log-model", "feature": {}},
        )
        assert missing.status_code == 401

        wrong = client.post(
            "/v1/score-once",
            headers={"X-API-Key": "wrong"},
            json={"model_name": "log-model", "feature": {}},
        )
        assert wrong.status_code == 401
    finally:
        settings.api_key = saved


def test_score_once_open_when_api_key_unconfigured(client: TestClient) -> None:
    saved = settings.api_key
    settings.api_key = ""
    try:
        # No API key header; endpoint is reachable (auth passes, then model call fails).
        resp = client.post(
            "/v1/score-once",
            json={"model_name": "log-model", "feature": {}},
        )
        assert resp.status_code in (400, 502)
        assert resp.status_code != 401
    finally:
        settings.api_key = saved
