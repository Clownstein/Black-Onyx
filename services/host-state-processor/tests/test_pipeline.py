import os

os.environ["HOST_STATE_PROCESSOR_ENABLE_KAFKA"] = "false"

from black_onyx_contracts import Finding

from host_state_processor.pipeline import FEATURE_VERSION, HostStatePipeline


def test_pipeline_emits_features_and_findings():
    pipeline = HostStatePipeline()
    events = [
        {
            "tenant_id": "tenant-acme",
            "occurred_at": "2026-07-26T20:41:02.123Z",
            "asset": {"asset_id": "host-payments-03", "service_id": "payments-api"},
            "payload": {
                "EventID": 1,
                "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                "ParentImage": r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
                "CommandLine": "powershell.exe -enc ZgBvAG8A",
                "ProcessId": 4242,
                "ParentProcessId": 1200,
                "User": r"NT AUTHORITY\SYSTEM",
            },
        },
        {
            "tenant_id": "tenant-acme",
            "occurred_at": "2026-07-26T20:41:05Z",
            "asset": {"asset_id": "host-payments-03"},
            "payload": {
                "name": "listening_ports",
                "port": 5555,
                "address": "0.0.0.0",
                "protocol": "tcp",
                "pid": 77,
                "process_name": "beacon.exe",
            },
        },
    ]
    features, findings = pipeline.process_events(events)
    assert len(features) == 1
    feature = features[0]
    assert feature["event_type"] == "host_state.features"
    assert feature["feature_version"] == FEATURE_VERSION
    assert feature["event_count"] == 2
    assert feature["asset_id"] == "host-payments-03"
    detectors = {d["detector"] for d in feature["detections"]}
    assert "suspicious_parent_child" in detectors
    assert "new_listening_port" in detectors
    assert len(findings) >= 2
    for finding in findings:
        validated = Finding.model_validate(finding)
        assert validated.finding_type == "host_state_rule"
        assert validated.model_name == "host-state-rules"
        assert validated.model_version == "1.0.0"
        assert 0.0 <= validated.calibrated_score <= 1.0
        assert validated.mitre_techniques


def test_pipeline_listening_port_novelty():
    pipeline = HostStatePipeline()
    base = {
        "tenant_id": "t1",
        "occurred_at": "2026-07-26T20:41:02Z",
        "asset": {"asset_id": "host-1"},
        "payload": {
            "name": "listening_ports",
            "port": 9999,
            "protocol": "tcp",
            "process_name": "odd.bin",
        },
    }
    features1, findings1 = pipeline.process_events([base])
    assert any(d["detector"] == "new_listening_port" for d in features1[0]["detections"])
    assert findings1
    features2, findings2 = pipeline.process_events([base])
    assert not any(d["detector"] == "new_listening_port" for d in features2[0]["detections"])
    assert findings2 == []


def test_pipeline_counts_normalize_errors():
    pipeline = HostStatePipeline()
    features, findings = pipeline.process_events([{"tenant_id": "t1", "payload": {}}])
    assert features == []
    assert findings == []
    assert pipeline.errors == 1
    assert pipeline.processed == 0
