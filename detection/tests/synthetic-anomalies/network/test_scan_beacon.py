from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
NETWORK_MODEL = ROOT / "models" / "network-model"
if str(NETWORK_MODEL) not in sys.path:
    sys.path.insert(0, str(NETWORK_MODEL))

from network_model.model import heuristic_score  # noqa: E402


def test_scan_and_beacon_score_higher_than_control() -> None:
    control = heuristic_score(
        {
            "flows": [
                {
                    "src_port": 54321,
                    "dst_port": 443,
                    "protocol": "tcp",
                    "bytes": 1200,
                    "packets": 10,
                    "dst_is_external": False,
                    "direction": "egress",
                }
            ],
            "aggregates": {
                "failed_connections": 0,
                "distinct_dst_ports": 2,
                "external_peers": 0,
            },
            "detections": [],
        }
    )

    scan = heuristic_score(
        {
            "flows": [],
            "aggregates": {
                "failed_connections": 40,
                "distinct_dst_ports": 80,
                "external_peers": 25,
            },
            "detections": [{"type": "port_scan", "score": 0.9}],
        }
    )
    beacon = heuristic_score(
        {
            "flows": [
                {
                    "src_port": 40000,
                    "dst_port": 443,
                    "protocol": "tcp",
                    "bytes": 64,
                    "packets": 1,
                    "dst_is_external": True,
                    "direction": "egress",
                    "peer_hash": "beacon-peer",
                }
            ]
            * 20,
            "aggregates": {
                "failed_connections": 2,
                "distinct_dst_ports": 1,
                "external_peers": 1,
            },
            "detections": [{"type": "beaconing", "score": 0.88}],
        }
    )

    assert scan["risk_score"] > control["risk_score"]
    assert beacon["risk_score"] > control["risk_score"]
