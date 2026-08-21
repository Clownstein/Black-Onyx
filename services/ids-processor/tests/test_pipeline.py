from pathlib import Path

from ids_processor.normalize import normalize_suricata_alert, suricata_severity_to_score
from ids_processor.pipeline import IdsPipeline


FIXTURE = Path(__file__).resolve().parents[3] / "contracts" / "network" / "examples" / "valid_suricata_alert.json"


def test_severity_mapping():
    assert suricata_severity_to_score(1) == ("critical", 0.95)
    assert suricata_severity_to_score(2) == ("high", 0.80)
    assert suricata_severity_to_score(3) == ("medium", 0.55)
    assert suricata_severity_to_score(4) == ("low", 0.30)


def test_normalize_fixture_alert():
    import json

    payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
    event = {
        "tenant_id": "tenant-acme",
        "occurred_at": "2026-07-27T14:00:00Z",
        "asset": {"asset_id": "host-web-01"},
        "event_type": "suricata.alert",
        "payload": payload,
    }
    row = normalize_suricata_alert(event)
    assert row["signature_id"] == 2100498
    assert row["signature"] == "ET SCAN Potential SSH Scan"
    assert row["community_id"] == "1:LQU9qZlK+B5F3Y8c6s0y9w=="
    assert row["asset_id"] == "host-web-01"
    assert row["severity_hint"] == "high"
    assert row["calibrated_score"] == 0.80
    assert "T1046" in row["mitre_techniques"]


def test_pipeline_emits_finding(monkeypatch):
    import json

    monkeypatch.setenv("IDS_PROCESSOR_ENABLE_KAFKA", "false")
    monkeypatch.setenv("IDS_PROCESSOR_PUBLISH_FINDINGS", "true")
    from ids_processor.config import Settings

    monkeypatch.setattr("ids_processor.pipeline.settings", Settings())
    payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
    pipeline = IdsPipeline()
    findings = pipeline.process_events(
        [
            {
                "tenant_id": "tenant-acme",
                "occurred_at": "2026-07-27T14:00:00Z",
                "asset": {"asset_id": "host-web-01"},
                "payload": payload,
            }
        ]
    )
    assert len(findings) == 1
    finding = findings[0]
    assert finding["finding_type"] == "suricata_alert"
    assert finding["calibrated_score"] == 0.80
    assert finding["severity_hint"] == "high"
    assert finding["context"]["signature_id"] == 2100498
    assert finding["context"]["signature"] == "ET SCAN Potential SSH Scan"
    assert finding["context"]["community_id"] == "1:LQU9qZlK+B5F3Y8c6s0y9w=="
    assert finding["context"]["asset_id"] == "host-web-01"
    assert "T1046" in finding["mitre_techniques"]


def test_pipeline_attaches_pcap_evidence(monkeypatch):
    import json

    monkeypatch.setenv("IDS_PROCESSOR_ENABLE_KAFKA", "false")
    monkeypatch.setenv("IDS_PROCESSOR_PUBLISH_FINDINGS", "true")
    from ids_processor.config import Settings

    monkeypatch.setattr("ids_processor.pipeline.settings", Settings())
    monkeypatch.setattr(
        "ids_processor.pipeline.evidence_ref_for_pcap",
        lambda data, *, asset_id, alert_id=None: {
            "type": "pcap",
            "uri": "s3://anomaly-pcap/pcap/test.pcap",
            "sha256": "abc",
            "size_bytes": len(data),
            "uploaded": False,
        },
    )
    payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
    pipeline = IdsPipeline()
    findings = pipeline.process_events(
        [
            {
                "tenant_id": "tenant-acme",
                "occurred_at": "2026-07-27T14:00:00Z",
                "asset": {"asset_id": "host-web-01"},
                "payload": payload,
                "pcap_bytes": b"\xd4\xc3\xb2\xa1fake-pcap",
            }
        ]
    )
    assert len(findings) == 1
    refs = findings[0]["evidence_refs"]
    assert refs
    assert refs[0]["type"] == "pcap"
    assert refs[0]["uri"].startswith("s3://")
