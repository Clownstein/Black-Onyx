from __future__ import annotations

from unittest.mock import MagicMock, patch

from correlation_engine.scoring import FindingView
from correlation_engine.threat_intel import (
    apply_threat_intel_boost,
    enrich_incident_with_threat_intel,
    extract_observables,
)


def test_extract_observables_from_context() -> None:
    findings = [
        FindingView(
            finding_id="f1",
            finding_type="network_anomaly",
            tenant_id="t1",
            asset_id="host-1",
            service_id="svc",
            calibrated_score=0.9,
            model_name="flow",
            context={"dst_ip": "203.0.113.50", "domain": "evil.example"},
        )
    ]
    obs = extract_observables(findings)
    types = {(o["type"], o["value"]) for o in obs}
    assert ("ipv4", "203.0.113.50") in types
    assert ("domain", "evil.example") in types


def test_extract_observables_from_nested_evidence() -> None:
    findings = [
        FindingView(
            finding_id="f1",
            finding_type="host_state_rule",
            tenant_id="t1",
            asset_id="host-1",
            service_id=None,
            calibrated_score=0.8,
            model_name="host-state-rules",
            context={
                "evidence": {
                    "socket": {"remote_ip": "198.51.100.20"},
                    "src_ip": "203.0.113.9",
                }
            },
        )
    ]
    obs = extract_observables(findings)
    types = {(o["type"], o["value"]) for o in obs}
    assert ("ipv4", "198.51.100.20") in types
    assert ("ipv4", "203.0.113.9") in types


def test_apply_boost_caps_at_015() -> None:
    incident = {"risk_score": 0.5, "context": {}}
    apply_threat_intel_boost(
        incident,
        {
            "matches": [
                {
                    "id": "ind-1",
                    "type": "ipv4",
                    "value": "203.0.113.50",
                    "confidence": 100,
                    "source": "cisa-kev",
                }
            ],
            "campaigns": ["c1"],
            "tlp": "amber",
        },
    )
    assert incident["risk_score"] == 0.65
    assert incident["context"]["threat_intel"]["tlp"] == "amber"
    assert incident["threat_intel"]["matched_indicators"][0]["id"] == "ind-1"


def test_enrich_noop_when_url_unset(monkeypatch) -> None:
    from correlation_engine.config import settings

    monkeypatch.setattr(settings, "threat_intel_url", "")
    incident = {"risk_score": 0.4, "context": {}}
    findings = [
        FindingView(
            finding_id="f1",
            finding_type="network_anomaly",
            tenant_id="t1",
            asset_id="host-1",
            service_id=None,
            calibrated_score=0.9,
            model_name="flow",
            context={"dst_ip": "203.0.113.50"},
        )
    ]
    enrich_incident_with_threat_intel(incident, findings)
    assert incident["risk_score"] == 0.4
    assert "threat_intel" not in incident.get("context", {})


def test_enrich_calls_match_api(monkeypatch) -> None:
    from correlation_engine.config import settings

    monkeypatch.setattr(settings, "threat_intel_url", "http://threat-intel:8098")

    class FakeResp:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict:
            return {
                "matches": [
                    {
                        "id": "ind-x",
                        "type": "ipv4",
                        "value": "203.0.113.50",
                        "confidence": 80,
                        "source": "taxii",
                    }
                ],
                "campaigns": [],
                "tlp": None,
            }

    class FakeClient:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def __enter__(self) -> FakeClient:
            return self

        def __exit__(self, *args) -> None:
            return None

        def post(self, url: str, **kwargs) -> FakeResp:
            assert url.endswith("/api/v1/match")
            assert kwargs["json"]["observables"]
            return FakeResp()

    incident = {"risk_score": 0.5, "context": {}}
    findings = [
        FindingView(
            finding_id="f1",
            finding_type="network_anomaly",
            tenant_id="t1",
            asset_id="host-1",
            service_id=None,
            calibrated_score=0.9,
            model_name="flow",
            context={"dst_ip": "203.0.113.50"},
        )
    ]
    with patch("correlation_engine.threat_intel.httpx.Client", FakeClient):
        enrich_incident_with_threat_intel(incident, findings)
    assert incident["risk_score"] == 0.62  # 0.5 + 0.15*0.8
    assert incident["context"]["threat_intel"]["matched_indicators"][0]["id"] == "ind-x"
