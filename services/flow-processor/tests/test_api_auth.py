from fastapi.testclient import TestClient

from flow_processor.config import settings
from flow_processor.main import app


def test_process_route_requires_configured_key_and_strict_body(monkeypatch):
    monkeypatch.setattr(settings, "enable_kafka", False)
    monkeypatch.setattr(settings, "api_key", "processor-secret")
    with TestClient(app) as client:
        assert client.post("/v1/process", json={"events": [{}]}).status_code == 401
        assert client.post("/v1/process", content=b"{}", headers={"Content-Length": str(17 * 1024 * 1024)}).status_code == 413
        assert client.post("/v1/process", headers={"X-API-Key": "processor-secret"}, json={"events": [], "extra": True}).status_code == 422
    monkeypatch.setattr(settings, "api_key", "")
    with TestClient(app) as client:
        assert client.post("/v1/process", json={"events": [{}]}).status_code == 503
