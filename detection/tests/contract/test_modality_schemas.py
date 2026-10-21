from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

# contracts/ lives at the repository root, not under detection/.
ROOT = Path(__file__).resolve().parents[3]
CONTRACTS = ROOT / "contracts"


@pytest.mark.parametrize(
    ("schema_rel", "example_rel"),
    [
        ("common/event_envelope.schema.json", "common/examples/valid_envelope.json"),
        ("findings/finding.schema.json", "findings/examples/valid_finding.json"),
        ("logs/log_raw.schema.json", "logs/examples/valid_log_raw.json"),
        ("logs/log_normalized.schema.json", "logs/examples/valid_log_normalized.json"),
        ("network/network_flow.schema.json", "network/examples/valid_network_flow.json"),
        ("network/zeek_conn.schema.json", "network/examples/valid_zeek_conn.json"),
        ("network/zeek_dns.schema.json", "network/examples/valid_zeek_dns.json"),
        ("network/zeek_ssl.schema.json", "network/examples/valid_zeek_ssl.json"),
        ("network/suricata_alert.schema.json", "network/examples/valid_suricata_alert.json"),
        ("network/pcap_excerpt.schema.json", "network/examples/valid_pcap_excerpt.json"),
        ("metrics/metric_sample.schema.json", "metrics/examples/valid_metric_sample.json"),
        ("code/code_change.schema.json", "code/examples/valid_code_change.json"),
        ("incidents/incident.schema.json", "incidents/examples/valid_incident.json"),
        ("host-state/host_state_event.schema.json", "host-state/examples/valid_process_event.json"),
        ("threat-intel/indicator.schema.json", "threat-intel/examples/valid_indicator.json"),
        ("threat-intel/match_result.schema.json", "threat-intel/examples/valid_match_result.json"),
        ("firewall/firewall_event.schema.json", "firewall/examples/valid_firewall_event.json"),
        ("malware/malware_submit.schema.json", "malware/examples/valid_malware_submit.json"),
        ("malware/malware_report.schema.json", "malware/examples/valid_malware_report.json"),
        ("profiles/security_pack.schema.json", "profiles/examples/valid_security_pack.json"),
        (
            "deployments/deployment_event.schema.json",
            "deployments/examples/valid_deployment_event.json",
        ),
        (
            "feedback/analyst_feedback.schema.json",
            "feedback/examples/valid_analyst_feedback.json",
        ),
    ],
)
def test_schema_examples_validate(schema_rel: str, example_rel: str) -> None:
    schema = json.loads((CONTRACTS / schema_rel).read_text(encoding="utf-8"))
    example = json.loads((CONTRACTS / example_rel).read_text(encoding="utf-8"))
    jsonschema.validate(instance=example, schema=schema)


@pytest.mark.parametrize(
    "schema_rel",
    [
        "logs/log_raw.schema.json",
        "logs/log_normalized.schema.json",
        "network/network_flow.schema.json",
        "metrics/metric_sample.schema.json",
        "code/code_change.schema.json",
        "incidents/incident.schema.json",
        "findings/finding.schema.json",
        "deployments/deployment_event.schema.json",
        "feedback/analyst_feedback.schema.json",
    ],
)
def test_modality_schemas_load(schema_rel: str) -> None:
    path = CONTRACTS / schema_rel
    assert path.is_file()
    schema = json.loads(path.read_text(encoding="utf-8"))
    assert schema.get("title")
    assert "properties" in schema
