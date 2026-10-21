from __future__ import annotations

from fastapi.testclient import TestClient

from black_onyx.api.app import create_app
from black_onyx.config import get_settings


def test_public_validation_errors_use_problem_details(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("QDRANT_STORAGE__STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("QDRANT_SECURITY__EXTERNAL_URL", "http://testserver")
    monkeypatch.setenv("BLACK_ONYX_AUTH_SECRET", "test-only-problem-details-secret")
    get_settings.cache_clear()
    app = create_app()
    client = TestClient(app, raise_server_exceptions=False)
    response = client.post(
        "/api/v1/auth/login",
        headers={"Origin": "http://testserver"},
        json={},
    )
    assert response.status_code == 422
    assert response.headers["content-type"].startswith("application/problem+json")
    assert response.json()["title"] == "Request validation failed"
    assert response.json()["request_id"]
    get_settings.cache_clear()
