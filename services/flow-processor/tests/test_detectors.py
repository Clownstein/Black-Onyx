from datetime import datetime, timedelta

from flow_processor.detectors import (
    detect_beaconing_heuristic,
    detect_cross_host_external_ip,
    detect_dns_tunneling_heuristic,
    detect_failed_connection_burst,
    detect_new_external_peer,
    detect_port_scan_heuristic,
    detect_rare_tls_fingerprint,
)
from flow_processor.windows import aggregate_window


def _flow(i: int, **kwargs):
    base = {
        "peer_hash": f"peer-{i % 2}",
        "dst_port": 80 + i,
        "dst_is_external": True,
        "src_is_external": False,
        "failed": False,
        "bytes": 10,
        "packets": 1,
        "protocol": "tcp",
        "occurred_at": (datetime(2024, 1, 1) + timedelta(seconds=i)).isoformat(),
        "asset_id": "a1",
        "tenant_id": "t1",
    }
    base.update(kwargs)
    return base


def test_new_external_peer():
    flows = [_flow(0, peer_hash="new-peer", dst_port=443)]
    window = {"flows": flows, "aggregates": aggregate_window(flows), "event_count": 1}
    hit = detect_new_external_peer(window, known_external_peers=set())
    assert hit is not None
    assert hit["detector"] == "new_external_peer"
    assert detect_new_external_peer(window, known_external_peers={"new-peer"}) is None


def test_port_scan_heuristic():
    flows = [_flow(i, peer_hash="scanner", dst_port=1000 + i, bytes=5) for i in range(15)]
    window = {
        "flows": flows,
        "aggregates": aggregate_window(flows),
        "event_count": len(flows),
    }
    hit = detect_port_scan_heuristic(window)
    assert hit is not None
    assert hit["detector"] == "port_scan_heuristic"


def test_failed_connection_burst():
    flows = [_flow(i, failed=True, dst_port=22) for i in range(8)]
    window = {
        "flows": flows,
        "aggregates": aggregate_window(flows),
        "event_count": len(flows),
    }
    hit = detect_failed_connection_burst(window)
    assert hit is not None
    assert hit["detector"] == "failed_connection_burst"


def test_beaconing_heuristic():
    # Near-periodic reconnects every ~60s to the same peer.
    flows = [
        _flow(
            i,
            peer_hash="beacon-peer",
            dst_port=443,
            occurred_at=(datetime(2024, 1, 1) + timedelta(seconds=i * 60)).isoformat(),
        )
        for i in range(6)
    ]
    window = {
        "flows": flows,
        "aggregates": aggregate_window(flows),
        "event_count": len(flows),
    }
    hit = detect_beaconing_heuristic(window)
    assert hit is not None
    assert hit["detector"] == "beaconing_heuristic"
    assert "T1071" in hit["mitre_techniques"]
    assert hit["evidence"]["peer_hash"] == "beacon-peer"


def test_beaconing_heuristic_irregular_skips():
    flows = [
        _flow(
            i,
            peer_hash="noisy-peer",
            occurred_at=(datetime(2024, 1, 1) + timedelta(seconds=gaps)).isoformat(),
        )
        for i, gaps in enumerate([0, 3, 90, 95, 400, 401])
    ]
    window = {"flows": flows, "event_count": len(flows)}
    assert detect_beaconing_heuristic(window) is None


def test_cross_host_external_ip():
    flows = [
        _flow(0, peer_hash="shared-ext", asset_id="host-a", dst_is_external=True),
        _flow(1, peer_hash="shared-ext", asset_id="host-b", dst_is_external=True),
        _flow(2, peer_hash="shared-ext", asset_id="host-c", dst_is_external=True),
    ]
    window = {
        "flows": flows,
        "aggregates": aggregate_window(flows),
        "event_count": len(flows),
        "asset_ids": ["host-a", "host-b", "host-c"],
    }
    hit = detect_cross_host_external_ip(window)
    assert hit is not None
    assert hit["detector"] == "cross_host_external_ip"
    assert hit["evidence"]["asset_count"] == 3
    assert "T1071" in hit["mitre_techniques"]


def test_cross_host_external_ip_single_asset_skips():
    flows = [
        _flow(i, peer_hash="solo-ext", asset_id="host-a", dst_is_external=True)
        for i in range(4)
    ]
    window = {"flows": flows, "event_count": len(flows)}
    assert detect_cross_host_external_ip(window) is None


def test_rare_tls_fingerprint():
    flows = [
        _flow(
            0,
            tls={"ja3": "newja3", "ja4": "newja4", "sni": "rare.example"},
        )
    ]
    window = {"flows": flows, "event_count": 1}
    hit = detect_rare_tls_fingerprint(window, known_ja3=set(), known_ja4=set(), known_sni=set())
    assert hit is not None
    assert hit["detector"] == "rare_tls_fingerprint"
    assert "newja3" in hit["evidence"]["novel_ja3"]
    assert detect_rare_tls_fingerprint(
        window,
        known_ja3={"newja3"},
        known_ja4={"newja4"},
        known_sni={"rare.example"},
    ) is None


def test_dns_tunneling_heuristic():
    long_q = "a" * 70 + ".exfil.example"
    flows = [
        _flow(
            0,
            dns={"query": long_q, "query_length": len(long_q), "entropy": 4.5},
        )
    ]
    window = {"flows": flows, "event_count": 1}
    hit = detect_dns_tunneling_heuristic(window)
    assert hit is not None
    assert hit["detector"] == "dns_tunneling_heuristic"
    assert "T1048" in hit["mitre_techniques"]


def test_dns_tunneling_short_query_skips():
    flows = [_flow(0, dns={"query": "a.com", "query_length": 5, "entropy": 1.2})]
    window = {"flows": flows, "event_count": 1}
    assert detect_dns_tunneling_heuristic(window) is None
