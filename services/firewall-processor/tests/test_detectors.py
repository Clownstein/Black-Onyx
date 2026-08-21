from firewall_processor.detectors import detect_deny_spike, detect_rule_change_outside_window
from firewall_processor.normalize import normalize_firewall_event
from firewall_processor.pipeline import FirewallPipeline


def test_normalize_deny_traffic():
    event = {
        "tenant_id": "t1",
        "asset_id": "fw-1",
        "occurred_at": "2024-06-01T12:00:00Z",
        "payload": {
            "action": "deny",
            "src_ip": "203.0.113.10",
            "dst_ip": "10.0.0.5",
            "dst_port": 22,
            "protocol": "tcp",
        },
    }
    row = normalize_firewall_event(event)
    assert row["is_deny"] is True
    assert row["src_ip"] == "203.0.113.10"
    assert row["event_type"] == "traffic"


def test_normalize_rule_add():
    event = {
        "tenant_id": "t1",
        "asset_id": "fw-1",
        "occurred_at": "2024-06-01T02:15:00Z",
        "payload": {
            "event_type": "rule_add",
            "rule_id": "ACL-42",
            "rule_name": "temp-allow",
            "action": "permit",
        },
    }
    row = normalize_firewall_event(event)
    assert row["event_type"] == "rule_add"
    assert row["rule_id"] == "ACL-42"


def test_deny_spike():
    events = [
        {
            "is_deny": True,
            "src_ip": "198.51.100.9",
            "dst_ip": f"10.0.0.{i}",
            "asset_id": "fw-1",
            "tenant_id": "t1",
            "occurred_at": "2024-06-01T12:00:00Z",
        }
        for i in range(25)
    ]
    hits = detect_deny_spike(events, threshold=20)
    assert len(hits) == 1
    assert hits[0]["detector"] == "deny_spike"
    assert hits[0]["evidence"]["deny_count"] == 25
    assert "T1190" in hits[0]["mitre_techniques"]


def test_rule_change_outside_window():
    event = {
        "event_type": "rule_delete",
        "occurred_at": "2024-06-01T02:30:00Z",
        "asset_id": "fw-1",
        "tenant_id": "t1",
        "rule_id": "R-1",
    }
    hit = detect_rule_change_outside_window(event)
    assert hit is not None
    assert hit["severity"] == "high"
    assert hit["detector"] == "rule_change_outside_window"


def test_rule_change_inside_window_skips():
    event = {
        "event_type": "rule_add",
        "occurred_at": "2024-06-01T14:00:00Z",
        "asset_id": "fw-1",
        "tenant_id": "t1",
    }
    assert detect_rule_change_outside_window(event) is None


def test_pipeline_emits_findings(monkeypatch):
    monkeypatch.setenv("FIREWALL_PROCESSOR_ENABLE_KAFKA", "false")
    monkeypatch.setenv("FIREWALL_PROCESSOR_PUBLISH_FINDINGS", "true")
    from firewall_processor.config import Settings

    monkeypatch.setattr("firewall_processor.pipeline.settings", Settings())
    pipeline = FirewallPipeline()
    features, findings = pipeline.process_events(
        [
            {
                "tenant_id": "t1",
                "asset_id": "fw-1",
                "occurred_at": "2024-06-01T03:00:00Z",
                "payload": {
                    "event_type": "rule_add",
                    "rule_id": "R-9",
                    "action": "permit",
                },
            }
        ]
    )
    assert features
    assert findings
    assert findings[0]["finding_type"] == "firewall_rule"
    assert findings[0]["context"]["detector"] == "rule_change_outside_window"
