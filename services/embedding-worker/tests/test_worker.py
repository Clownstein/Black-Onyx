from unittest.mock import MagicMock

from embedding_worker import worker
from embedding_worker.config import settings


def _finding() -> dict:
    return {
        "tenant_id": "t1",
        "finding_id": "f-123",
        "finding_type": "network.flow_anomaly",
        "asset_id": "asset-checkout-01",
        "service_id": "checkout",
        "model_name": "network-model",
        "calibrated_score": 0.86,
        "severity_hint": "high",
        "modality": "network",
        "contributors": [{"type": "new_external_peer"}, {"weight": 0.2}],
        "context": {"mitre_techniques": ["T1071"]},
        "window": {"start": "2026-07-27T13:45:00Z", "end": "2026-07-27T14:00:00Z"},
        "summary_text": "New external peer with periodic egress from checkout",
    }


def test_build_payload_shapes_findings_v1_fields():
    payload = worker.build_finding_payload(_finding())
    assert payload["tenant_id"] == "t1"
    assert payload["finding_id"] == "f-123"
    assert payload["calibrated_score"] == 0.86
    assert payload["occurred_at_ts"] > 0
    assert payload["contributor_types"] == ["new_external_peer"]
    assert payload["mitre_techniques"] == ["T1071"]
    assert payload["embed_version"] == "1"


def test_process_finding_disabled_path(monkeypatch):
    monkeypatch.setattr(settings, "vector_search_enabled", False)
    result = worker.process_finding(_finding())
    assert result["status"] == "disabled"


def test_process_finding_skips_missing_ids(monkeypatch):
    monkeypatch.setattr(settings, "vector_search_enabled", True)
    result = worker.process_finding({"tenant_id": "t1"})
    assert result["status"] == "skipped"


def test_process_finding_upserts_when_enabled(monkeypatch, fake_embedding_model):
    monkeypatch.setattr(settings, "vector_search_enabled", True)
    monkeypatch.setattr(worker, "_collections_ready", True)

    mock_client = MagicMock()
    monkeypatch.setattr(worker, "vector_client", lambda: mock_client)

    result = worker.process_finding(_finding())

    assert result["status"] == "upserted"
    assert result["finding_id"] == "f-123"
    assert result["dim"] == 768
    mock_client.upsert.assert_called_once()
    args, kwargs = mock_client.upsert.call_args
    assert args[0] == "findings_v1"
    point = args[1][0]
    assert point["id"] == "f-123"
    assert len(point["vector"]["dense"]) == 768
    assert point["payload"]["tenant_id"] == "t1"


def test_process_finding_soft_fails_on_upsert_error(monkeypatch, fake_embedding_model):
    monkeypatch.setattr(settings, "vector_search_enabled", True)
    monkeypatch.setattr(worker, "_collections_ready", True)

    mock_client = MagicMock()
    mock_client.upsert.side_effect = RuntimeError("qdrant down")
    monkeypatch.setattr(worker, "vector_client", lambda: mock_client)

    result = worker.process_finding(_finding())
    assert result["status"] == "degraded"
    assert result["capability"] == "vector_storage"
    assert "qdrant down" in result["reason"]
