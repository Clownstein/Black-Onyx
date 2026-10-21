from fastapi.testclient import TestClient

from security_runner.app import app


def test_health_is_public(monkeypatch):
    monkeypatch.setenv("SECURITY_RUNNER_TOKEN", "runner-test-token")
    response = TestClient(app).get("/healthz")

    assert response.status_code == 200
    assert response.json() == {"status": "alive"}


def test_execute_authenticates_before_body_validation(monkeypatch):
    monkeypatch.setenv("SECURITY_RUNNER_TOKEN", "runner-test-token")
    response = TestClient(app).post("/execute", json={})

    assert response.status_code == 401
    assert response.json() == {"detail": "Authentication required"}


def test_authenticated_invalid_body_reaches_schema_validation(monkeypatch):
    monkeypatch.setenv("SECURITY_RUNNER_TOKEN", "runner-test-token")
    response = TestClient(app).post(
        "/execute",
        json={},
        headers={"Authorization": "Bearer runner-test-token"},
    )

    assert response.status_code == 422
