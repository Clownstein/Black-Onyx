from __future__ import annotations

import httpx
import respx
from profile_evaluator.config import settings
from profile_evaluator.main import app
from fastapi.testclient import TestClient

BASE = settings.incident_api_url.rstrip("/")


def test_health_live() -> None:
    with TestClient(app) as client:
        resp = client.get("/health/live")
    assert resp.status_code == 200
    assert resp.json()["status"] == "alive"


def test_health_ready_reports_config() -> None:
    with TestClient(app) as client:
        resp = client.get("/health/ready")
    body = resp.json()
    assert resp.status_code == 200
    assert body["status"] == "ready"
    assert body["loop_enabled"] is False
    assert body["vector_novelty_enabled"] is False


@respx.mock
def test_evaluate_endpoint_runs_cycle() -> None:
    respx.get(f"{BASE}/api/v1/security-profiles").mock(
        return_value=httpx.Response(200, json={"items": []})
    )
    with TestClient(app) as client:
        resp = client.post("/api/v1/profile-evaluator/evaluate")
    assert resp.status_code == 200
    body = resp.json()
    assert body["active_count"] == 0
    assert body["emitted_findings"] == []
