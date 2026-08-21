"""Unit tests for OpenSearch hunt proxy."""

from __future__ import annotations

from fastapi.testclient import TestClient


def test_hunt_search_proxies_hits(monkeypatch) -> None:
    from incident_api import opensearch_client
    from incident_api.main import app

    def fake_search(*, tenant_id: str, query: str, size: int = 50):
        assert tenant_id == "tenant-acme"
        assert query == "egress"
        assert size == 10
        return {
            "hits": {
                "total": {"value": 1},
                "hits": [
                    {
                        "_index": "aa-findings-2024.06.01",
                        "_id": "f-1",
                        "_score": 1.2,
                        "_source": {
                            "doc_type": "finding",
                            "title": "Suspicious egress",
                            "tenant_id": tenant_id,
                        },
                    }
                ],
            }
        }

    monkeypatch.setattr(opensearch_client, "search", fake_search)
    client = TestClient(app)
    resp = client.get(
        "/api/v1/hunt/search",
        params={"q": "egress", "size": 10},
        headers={"X-Tenant-Id": "tenant-acme"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["tenant_id"] == "tenant-acme"
    assert body["total"] == 1
    assert body["hits"][0]["id"] == "f-1"
    assert body["hits"][0]["source"]["title"] == "Suspicious egress"


def test_hunt_search_maps_backend_errors(monkeypatch) -> None:
    from incident_api import opensearch_client
    from incident_api.main import app

    def boom(*, tenant_id: str, query: str, size: int = 50):
        raise RuntimeError("connection refused")

    monkeypatch.setattr(opensearch_client, "search", boom)
    client = TestClient(app)
    resp = client.get(
        "/api/v1/hunt/search",
        params={"q": "x"},
        headers={"X-Tenant-Id": "tenant-acme"},
    )
    assert resp.status_code == 502
    assert "unavailable" in resp.json()["detail"].lower()
