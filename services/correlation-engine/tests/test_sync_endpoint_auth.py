from fastapi.testclient import TestClient

from correlation_engine import main
from correlation_engine.config import settings


def _client(monkeypatch, enabled=True, key="k" * 32):
    monkeypatch.setattr(settings, "sync_endpoint_enabled", enabled)
    monkeypatch.setattr(settings, "api_key", key)
    monkeypatch.setattr(main.engine, "ingest_finding", lambda finding: {"tenant_id": finding["tenant_id"]})
    return TestClient(main.app)


def test_sync_endpoint_disabled_by_default(monkeypatch):
    client = _client(monkeypatch, enabled=False)
    assert client.post("/v1/correlate", json={}).status_code == 404


def test_sync_endpoint_requires_key_and_tenant(monkeypatch):
    client = _client(monkeypatch)
    assert client.post("/v1/correlate", json={}).status_code == 401
    assert client.post("/v1/correlate", json={}, headers={"X-API-Key": "wrong"}).status_code == 401
    assert client.post("/v1/correlate", json={}, headers={"X-API-Key": "k" * 32}).status_code == 400
    assert _client(monkeypatch, key="").post(
        "/v1/correlate", json={}, headers={"X-API-Key": "x", "X-Tenant-Id": "t"}
    ).status_code == 503


def test_sync_endpoint_binds_tenant(monkeypatch):
    client = _client(monkeypatch)
    headers = {"X-API-Key": "k" * 32, "X-Tenant-Id": "tenant-a"}
    assert client.post("/v1/correlate", json={"tenant_id": "tenant-b"}, headers=headers).status_code == 403
    ok = client.post("/v1/correlate", json={"finding_id": "f"}, headers=headers)
    assert ok.status_code == 200
    assert ok.json()["incident"]["tenant_id"] == "tenant-a"
