#!/usr/bin/env python3
"""Offline dry-run for selective PCAP → Zeek/Suricata → gateway pipeline.

Documents the expected hand-off without requiring live sensors or Kafka:

  pcap excerpt
    → (optional) Zeek/Suricata offline parsers produce JSON
    → ingestion-gateway accepts network.flow / suricata.alert envelopes
    → flow-processor / ids-processor feature+finding path

Use ``--dry-run`` (default) to validate fixture envelopes only.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CONTRACTS = ROOT / "contracts" / "network" / "examples"


def _load(name: str) -> dict:
    path = CONTRACTS / name
    if not path.is_file():
        raise FileNotFoundError(path)
    return json.loads(path.read_text(encoding="utf-8"))


def synthesize_pcap_bytes() -> bytes:
    """Tiny benign PCAP-like header (not a real capture — CI-safe)."""
    # Global header magic + version + snaplen placeholder
    return b"\xd4\xc3\xb2\xa1" + b"\x02\x00\x04\x00" + b"\x00" * 16


def build_pipeline_plan(pcap_sha256: str) -> dict:
    flow = _load("valid_network_flow.json")
    suricata = _load("valid_suricata_alert.json")
    zeek = _load("valid_zeek_conn.json") if (CONTRACTS / "valid_zeek_conn.json").is_file() else None
    return {
        "stages": [
            {
                "name": "pcap_excerpt",
                "sha256": pcap_sha256,
                "object_uri_template": "s3://anomaly-pcap/pcap/{asset_id}/{alert_id}.pcap",
            },
            {
                "name": "sensor_parse",
                "tools": ["zeek", "suricata"],
                "outputs": ["zeek.conn", "suricata.alert", "network.flow"],
            },
            {
                "name": "ingestion_gateway",
                "routes": [
                    "POST /api/v1/ingest/network-flows",
                    "POST /api/v1/ingest/suricata (or generic envelope → suricata.raw)",
                ],
            },
            {
                "name": "processors",
                "flow_processor": "network.raw → network.features",
                "ids_processor": "suricata.raw → findings.network",
            },
        ],
        "fixtures": {
            "network_flow": flow.get("event_type") or flow.get("src_ip") is not None,
            "suricata_alert": bool(suricata.get("alert") or suricata.get("signature_id") or suricata.get("event_type")),
            "zeek_conn": zeek is not None,
        },
        "dry_run": True,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true", default=True)
    parser.add_argument("--json", action="store_true", help="Print machine-readable plan")
    args = parser.parse_args(argv)

    pcap = synthesize_pcap_bytes()
    digest = hashlib.sha256(pcap).hexdigest()
    plan = build_pipeline_plan(digest)

    # Validate fixtures are readable JSON (offline contract smoke).
    assert plan["fixtures"]["network_flow"], "network flow fixture missing"
    assert plan["fixtures"]["suricata_alert"], "suricata fixture missing"

    if args.json:
        print(json.dumps(plan, indent=2))
    else:
        print("PCAP pipeline dry-run OK")
        print(f"  synthetic_pcap_sha256={digest}")
        for stage in plan["stages"]:
            print(f"  stage: {stage['name']}")
        print(f"  fixtures: {plan['fixtures']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
