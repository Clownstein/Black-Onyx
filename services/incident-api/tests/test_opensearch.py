"""Unit tests for OpenSearch best-effort writer helpers."""

from __future__ import annotations

from types import SimpleNamespace

from incident_api.opensearch_client import finding_doc_from_row, index_document, incident_doc_from_row


def test_index_document_never_raises_when_disabled(monkeypatch) -> None:
    from incident_api.config import settings

    monkeypatch.setattr(settings, "opensearch_indexing", False)
    index_document("finding", "f-1", {"tenant_id": "t"})


def test_doc_builders() -> None:
    finding = SimpleNamespace(
        tenant_id="t1",
        finding_id="f1",
        finding_type="log_anomaly",
        asset_id="a1",
        service_id="s1",
        model_name="log-model",
        calibrated_score=0.9,
        severity_hint="high",
        window_start=None,
        window_end=None,
        payload={"title": "spike", "mitre_techniques": ["T1071"]},
    )
    doc = finding_doc_from_row(finding)
    assert doc["finding_id"] == "f1"
    assert doc["mitre_techniques"] == ["T1071"]

    incident = SimpleNamespace(
        tenant_id="t1",
        incident_id="i1",
        title="inc",
        summary="sum",
        status="open",
        severity="high",
        risk_score=0.8,
        assets=["a1"],
        services=["s1"],
        finding_ids=["f1"],
        first_seen=None,
        last_seen=None,
        context={
            "site_id": "dc1",
            "threat_intel": {"matched_indicators": [{"id": "ind-1"}]},
        },
    )
    idoc = incident_doc_from_row(incident)
    assert idoc["incident_id"] == "i1"
    assert idoc["doc_type"] == "incident"
    assert idoc["site_id"] == "dc1"
    assert idoc["threat_intel"]["matched_indicators"][0]["id"] == "ind-1"
    assert idoc["context"]["site_id"] == "dc1"
