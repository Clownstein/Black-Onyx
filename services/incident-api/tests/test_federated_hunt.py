"""Tests for federated hunt endpoint (Milestone I)."""

from __future__ import annotations

from fastapi.testclient import TestClient


def _fake_os_result(tenant_id: str) -> dict:
    return {
        "hits": {
            "total": {"value": 1},
            "hits": [
                {
                    "_index": "aa-findings-2024.06.01",
                    "_id": "f-1",
                    "_score": 2.5,
                    "_source": {
                        "doc_type": "finding",
                        "title": "Suspicious egress",
                        "summary": "beacon to 203.0.113.5",
                        "tenant_id": tenant_id,
                    },
                }
            ],
        }
    }


def test_federated_hunt_opensearch_only_when_flag_off(monkeypatch):
    from incident_api import opensearch_client
    from incident_api.config import settings
    from incident_api.main import app

    monkeypatch.setattr(settings, "federated_hunt_enabled", False)
    monkeypatch.setattr(settings, "vector_search_enabled", False)

    captured = {}

    def fake_search(*, tenant_id: str, query: str, size: int = 50):
        captured["tenant_id"] = tenant_id
        captured["query"] = query
        return _fake_os_result(tenant_id)

    monkeypatch.setattr(opensearch_client, "search", fake_search)
    client = TestClient(app)
    resp = client.post(
        "/api/v1/hunt/federated",
        json={"query": "egress", "size": 10},
        headers={"X-Tenant-Id": "tenant-acme"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert captured["tenant_id"] == "tenant-acme"
    assert body["tenant_id"] == "tenant-acme"
    assert body["hits"], "expected opensearch hit"
    assert all(h["source"] == "opensearch" for h in body["hits"])
    assert any("FEDERATED_HUNT_ENABLED=false" in w for w in body["warnings"])


def test_federated_hunt_requires_tenant():
    from incident_api.main import app

    client = TestClient(app)
    resp = client.post("/api/v1/hunt/federated", json={"query": "x"})
    assert resp.status_code == 400


def test_federated_hunt_opensearch_error_soft_fails(monkeypatch):
    from incident_api import opensearch_client
    from incident_api.config import settings
    from incident_api.main import app

    monkeypatch.setattr(settings, "federated_hunt_enabled", True)
    monkeypatch.setattr(settings, "vector_search_enabled", False)
    monkeypatch.setattr(settings, "threat_intel_url", None)

    def boom(*, tenant_id: str, query: str, size: int = 50):
        raise RuntimeError("connection refused")

    monkeypatch.setattr(opensearch_client, "search", boom)
    client = TestClient(app)
    resp = client.post(
        "/api/v1/hunt/federated",
        json={"query": "egress"},
        headers={"X-Tenant-Id": "tenant-acme"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["hits"] == []
    assert any("opensearch_unavailable" in w for w in body["warnings"])


def test_federated_hunt_tenant_scoped_to_opensearch(monkeypatch):
    from incident_api import opensearch_client
    from incident_api.config import settings
    from incident_api.main import app

    monkeypatch.setattr(settings, "federated_hunt_enabled", True)
    monkeypatch.setattr(settings, "vector_search_enabled", False)
    monkeypatch.setattr(settings, "threat_intel_url", None)

    seen_tenants = []

    def fake_search(*, tenant_id: str, query: str, size: int = 50):
        seen_tenants.append(tenant_id)
        return _fake_os_result(tenant_id)

    monkeypatch.setattr(opensearch_client, "search", fake_search)
    client = TestClient(app)
    client.post(
        "/api/v1/hunt/federated",
        json={"query": "egress"},
        headers={"X-Tenant-Id": "tenant-a"},
    )
    client.post(
        "/api/v1/hunt/federated",
        json={"query": "egress"},
        headers={"X-Tenant-Id": "tenant-b"},
    )
    assert seen_tenants == ["tenant-a", "tenant-b"]
