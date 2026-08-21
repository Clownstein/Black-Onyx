from __future__ import annotations

from datetime import datetime, timedelta, timezone

from correlation_engine.kill_chains import (
    HOST_NETWORK_KILL_CHAIN_BOOST,
    KILL_CHAIN_BOOST,
    MALWARE_C2_NETWORK_BOOST,
    SURICATA_FLOW_BOOST,
    apply_kill_chain_boost,
    detect_code_metrics_network_kill_chain,
    detect_host_network_kill_chain,
    detect_malware_c2_network,
    detect_suricata_flow_coincidence,
)
from correlation_engine.scoring import FindingView


def _f(
    finding_id: str,
    finding_type: str,
    *,
    minutes_ago: int = 0,
    score: float = 0.8,
    context: dict | None = None,
    contributors: list | None = None,
    model_name: str | None = None,
) -> FindingView:
    end = datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)
    return FindingView(
        finding_id=finding_id,
        finding_type=finding_type,
        tenant_id="t1",
        asset_id="a1",
        service_id="svc",
        calibrated_score=score,
        model_name=model_name or finding_type.replace("_", "-"),
        contributors=contributors or [],
        context=context or {},
        window_start=end - timedelta(minutes=5),
        window_end=end,
    )


def test_detect_kill_chain_when_three_modalities_in_window() -> None:
    findings = [
        _f("c1", "code_anomaly", minutes_ago=2),
        _f("m1", "metrics_anomaly", minutes_ago=1),
        _f("n1", "network_anomaly", minutes_ago=0),
    ]
    hit = detect_code_metrics_network_kill_chain(findings, window_minutes=30)
    assert hit is not None
    assert hit["kill_chain"] == "code_metrics_network"
    assert hit["boost"] == KILL_CHAIN_BOOST


def test_no_kill_chain_when_modality_missing() -> None:
    findings = [
        _f("c1", "code_anomaly"),
        _f("m1", "metrics_anomaly"),
    ]
    assert detect_code_metrics_network_kill_chain(findings) is None


def test_no_kill_chain_outside_window() -> None:
    findings = [
        _f("c1", "code_anomaly", minutes_ago=120),
        _f("m1", "metrics_anomaly", minutes_ago=1),
        _f("n1", "network_anomaly", minutes_ago=0),
    ]
    assert detect_code_metrics_network_kill_chain(findings, window_minutes=30) is None


def test_apply_boost_updates_incident() -> None:
    findings = [
        _f("c1", "code_anomaly"),
        _f("m1", "metrics_anomaly"),
        _f("n1", "network_anomaly"),
    ]
    incident = {"risk_score": 0.5, "context": {}, "category": ["anomaly"]}
    apply_kill_chain_boost(incident, findings)
    assert incident["risk_score"] == round(0.5 + KILL_CHAIN_BOOST, 4)
    assert "kill_chain" in incident["category"]
    assert incident["context"]["kill_chain"]["kill_chain"] == "code_metrics_network"


def test_host_network_kill_chain() -> None:
    findings = [
        _f("h1", "host_state_rule", minutes_ago=1),
        _f("n1", "network_beacon", minutes_ago=0),
    ]
    hit = detect_host_network_kill_chain(findings)
    assert hit is not None
    assert hit["kill_chain"] == "host_network"
    assert hit["boost"] == HOST_NETWORK_KILL_CHAIN_BOOST

    incident = {"risk_score": 0.4, "context": {}, "category": []}
    apply_kill_chain_boost(incident, findings)
    assert incident["risk_score"] == round(0.4 + HOST_NETWORK_KILL_CHAIN_BOOST, 4)
    assert "host_network" in incident["category"]


def test_suricata_flow_coincidence_boost() -> None:
    cid = "1:abc"
    findings = [
        _f(
            "s1",
            "suricata_alert",
            minutes_ago=1,
            context={"signature_id": 2100498, "community_id": cid, "asset_id": "a1"},
            contributors=[{"type": "suricata_alert", "contribution": 0.8}],
            model_name="suricata-ids",
        ),
        _f(
            "n1",
            "network_anomaly",
            minutes_ago=0,
            context={"community_id": cid, "asset_id": "a1"},
            contributors=[{"type": "new_external_peer", "contribution": 0.9}],
            model_name="network-model",
        ),
    ]
    hit = detect_suricata_flow_coincidence(findings)
    assert hit is not None
    assert hit["kill_chain"] == "suricata_flow"
    assert hit["boost"] >= SURICATA_FLOW_BOOST
    assert any(k.startswith("community_id:") for k in hit["join_keys"])


def test_malware_c2_network_boost() -> None:
    findings = [
        _f(
            "m1",
            "malware_analysis",
            minutes_ago=1,
            context={"network": {"hosts": ["203.0.113.50"]}},
            model_name="malware-static",
        ),
        _f(
            "n1",
            "network_anomaly",
            minutes_ago=0,
            context={"dst": "203.0.113.50"},
            model_name="network-model",
        ),
    ]
    hit = detect_malware_c2_network(findings)
    assert hit is not None
    assert hit["kill_chain"] == "malware_c2_network"
    assert hit["boost"] == MALWARE_C2_NETWORK_BOOST
    assert "203.0.113.50" in hit["overlap"]
