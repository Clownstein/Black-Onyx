"""Unit tests for the black_onyx_vector client (no live Qdrant required)."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from black_onyx_vector import (
    COLLECTION_NAMES,
    COLLECTIONS,
    DENSE_SIZE,
    GLOBAL_TENANT,
    VectorClient,
)


def _client_with_mock() -> tuple[VectorClient, MagicMock]:
    mock = MagicMock()
    return VectorClient(client=mock), mock


def test_expected_collections_and_dense_size() -> None:
    assert set(COLLECTION_NAMES) == {
        "findings_v1",
        "incidents_v1",
        "features_baseline_v1",
        "ti_text_v1",
        "attack_tech_v1",
        "runbooks_v1",
    }
    # Dense text collections are 768-d Cosine.
    for name in ("findings_v1", "incidents_v1", "ti_text_v1", "attack_tech_v1", "runbooks_v1"):
        spec = COLLECTIONS[name]
        assert spec.vectors["dense"] == DENSE_SIZE
        assert spec.distance == "Cosine"
    # Baseline collection carries modality-specific named vectors (code = 768).
    baseline = COLLECTIONS["features_baseline_v1"]
    assert baseline.vectors["code"] == DENSE_SIZE
    assert set(baseline.vectors) == {"log", "network", "metrics", "code", "host_state"}


def test_tenant_filter_always_injects_tenant() -> None:
    flt = VectorClient.tenant_filter("tenant-acme")
    assert flt == {"must": [{"key": "tenant_id", "match": {"value": "tenant-acme"}}]}


def test_tenant_filter_with_extra_must() -> None:
    flt = VectorClient.tenant_filter(
        "tenant-acme",
        extra_must=[{"key": "modality", "match": {"value": "network"}}],
    )
    assert flt["must"][0] == {"key": "tenant_id", "match": {"value": "tenant-acme"}}
    assert {"key": "modality", "match": {"value": "network"}} in flt["must"]


def test_tenant_filter_include_global() -> None:
    flt = VectorClient.tenant_filter("tenant-acme", include_global=True)
    values = {c["match"]["value"] for c in flt["should"]}
    assert values == {"tenant-acme", GLOBAL_TENANT}


def test_tenant_filter_requires_tenant() -> None:
    with pytest.raises(ValueError):
        VectorClient.tenant_filter("")


def test_ensure_collections_creates_missing() -> None:
    client, mock = _client_with_mock()
    mock.collection_exists.return_value = False

    created = client.ensure_collections(["findings_v1"])

    assert created == ["findings_v1"]
    mock.create_collection.assert_called_once()
    _, kwargs = mock.create_collection.call_args
    assert kwargs["collection_name"] == "findings_v1"
    assert "dense" in kwargs["vectors_config"]
    # findings_v1 declares sparse vectors.
    assert kwargs["sparse_vectors_config"] is not None
    # Payload indexes are created best-effort for indexed fields.
    assert mock.create_payload_index.called


def test_ensure_collections_skips_existing() -> None:
    client, mock = _client_with_mock()
    mock.collection_exists.return_value = True

    created = client.ensure_collections(["findings_v1"])

    assert created == []
    mock.create_collection.assert_not_called()


def test_upsert_rejects_missing_tenant() -> None:
    client, mock = _client_with_mock()
    with pytest.raises(ValueError):
        client.upsert(
            "findings_v1",
            [{"id": "f1", "vector": {"dense": [0.0] * DENSE_SIZE}, "payload": {}}],
        )
    mock.upsert.assert_not_called()


def test_upsert_passes_points_with_tenant() -> None:
    client, mock = _client_with_mock()
    client.upsert(
        "findings_v1",
        [
            {
                "id": "f1",
                "vector": {"dense": [0.0] * DENSE_SIZE},
                "payload": {"tenant_id": "t1", "finding_id": "f1"},
            }
        ],
    )
    mock.upsert.assert_called_once()
    _, kwargs = mock.upsert.call_args
    assert kwargs["collection_name"] == "findings_v1"
    assert kwargs["wait"] is True
    assert len(kwargs["points"]) == 1


def test_search_injects_tenant_filter_and_normalizes_hits() -> None:
    client, mock = _client_with_mock()
    hit = MagicMock()
    hit.id = "f2"
    hit.score = 0.87
    hit.payload = {"finding_id": "f2", "tenant_id": "t1"}
    mock.search.return_value = [hit]

    results = client.search("findings_v1", [0.1] * DENSE_SIZE, "t1", limit=5)

    assert results == [
        {"id": "f2", "score": 0.87, "payload": {"finding_id": "f2", "tenant_id": "t1"}}
    ]
    _, kwargs = mock.search.call_args
    assert kwargs["collection_name"] == "findings_v1"
    assert kwargs["limit"] == 5
    assert kwargs["query_vector"] == ("dense", [0.1] * DENSE_SIZE)
    # A tenant filter object was passed through.
    assert kwargs["query_filter"] is not None


def test_search_requires_tenant() -> None:
    client, _ = _client_with_mock()
    with pytest.raises(ValueError):
        client.search("findings_v1", [0.0] * DENSE_SIZE, "")


def test_recommend_uses_positive_ids_and_tenant() -> None:
    client, mock = _client_with_mock()
    mock.recommend.return_value = [{"id": "f9", "score": 0.5, "payload": {"finding_id": "f9"}}]

    results = client.recommend("findings_v1", ["f1"], "t1", limit=3)

    assert results[0]["id"] == "f9"
    _, kwargs = mock.recommend.call_args
    assert kwargs["positive"] == ["f1"]
    assert kwargs["using"] == "dense"
    assert kwargs["limit"] == 3
    assert kwargs["query_filter"] is not None


def test_unavailable_client_raises() -> None:
    client = VectorClient(url=None)
    assert client.available is False
    with pytest.raises(RuntimeError):
        client.ensure_collections()
