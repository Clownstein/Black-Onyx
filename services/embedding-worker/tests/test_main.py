from unittest.mock import patch

from embedding_worker.main import app
from fastapi.testclient import TestClient


def _client() -> TestClient:
    with patch("embedding_worker.main.consumer.start"), patch("embedding_worker.main.consumer.stop"):
        return TestClient(app)


def test_health_live_and_ready(fake_embedding_model):
    client = _client()
    assert client.get("/health/live").json()["status"] == "alive"
    ready = client.get("/health/ready").json()
    assert "vector_search_enabled" in ready
    assert ready["embedding_ready"] is True


def test_embed_text_returns_768(fake_embedding_model):
    client = _client()
    resp = client.post("/api/v1/embed/text", json={"text": "beaconing egress"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["dim"] == 768
    assert len(body["vector"]) == 768


def test_embed_finding_disabled_returns_disabled():
    client = _client()
    resp = client.post(
        "/api/v1/embed/finding",
        json={"tenant_id": "t1", "finding_id": "f1", "finding_type": "log.anomaly"},
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "disabled"
