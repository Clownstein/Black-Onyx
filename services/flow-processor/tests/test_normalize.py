from datetime import timezone

from flow_processor.normalize import _parse_ts, hash_ip, normalize_flow
from flow_processor.zeek_adapter import zeek_to_flow_event


def test_parse_ts_epoch_seconds_is_tz_aware_utc():
    # Regression: _parse_ts previously used the naive datetime.utcfromtimestamp,
    # which drifted from firewall_processor's tz-aware equivalent.
    parsed = _parse_ts(1704067200)  # 2024-01-01T00:00:00Z
    assert parsed.tzinfo is not None
    assert parsed.astimezone(timezone.utc).isoformat() == "2024-01-01T00:00:00+00:00"


def test_parse_ts_naive_string_assumed_utc():
    parsed = _parse_ts("2024-01-01T00:00:00")
    assert parsed.tzinfo is not None
    assert parsed.astimezone(timezone.utc).isoformat() == "2024-01-01T00:00:00+00:00"


def test_normalize_flow_occurred_at_uses_z_suffix():
    event = {
        "tenant_id": "t1",
        "occurred_at": 1704067200,
        "asset": {"asset_id": "svc-a"},
        "payload": {
            "src_ip": "10.0.0.5",
            "dst_ip": "8.8.8.8",
            "dst_port": 443,
            "protocol": "tcp",
        },
    }
    flow = normalize_flow(event, "salt")
    assert flow["occurred_at"] == "2024-01-01T00:00:00Z"


def test_hash_ip_deterministic():
    a = hash_ip("1.2.3.4", "salt")
    b = hash_ip("1.2.3.4", "salt")
    assert a == b
    assert a != hash_ip("1.2.3.5", "salt")
    assert len(a) == 32


def test_normalize_flow_hashes_ips():
    event = {
        "tenant_id": "t1",
        "occurred_at": "2024-01-01T00:00:00Z",
        "asset": {"asset_id": "svc-a"},
        "payload": {
            "src_ip": "10.0.0.5",
            "dst_ip": "8.8.8.8",
            "dst_port": 443,
            "protocol": "tcp",
            "bytes": 1200,
            "packets": 10,
            "connection_state": "established",
        },
    }
    flow = normalize_flow(event, "salt")
    assert flow["src_ip_hash"] == hash_ip("10.0.0.5", "salt")
    assert flow["dst_ip_hash"] == hash_ip("8.8.8.8", "salt")
    assert flow["direction"] == "egress"
    assert flow["dst_is_external"] is True
    assert "8.8.8.8" not in str(flow)


def test_normalize_flow_wires_tls_and_dns():
    event = {
        "tenant_id": "t1",
        "occurred_at": "2024-01-01T00:00:00Z",
        "asset": {"asset_id": "svc-a"},
        "payload": {
            "src_ip": "10.0.0.5",
            "dst_ip": "8.8.8.8",
            "dst_port": 443,
            "protocol": "tcp",
            "bytes": 100,
            "packets": 2,
            "tls": {
                "sni": "API.Example.COM",
                "ja3": "AABB",
                "ja4": "t13d",
            },
            "dns": {
                "query": "exfil.evil.example",
                "qtype": "TXT",
                "entropy": 4.2,
                "query_length": 17,
            },
        },
    }
    flow = normalize_flow(event, "salt")
    assert flow["tls"]["sni"] == "api.example.com"
    assert flow["tls"]["ja3"] == "aabb"
    assert flow["tls"]["ja4"] == "t13d"
    assert flow["dns"]["query"] == "exfil.evil.example"
    assert flow["dns"]["entropy"] == 4.2


def test_zeek_ssl_adapter_to_normalize():
    event = {
        "tenant_id": "t1",
        "event_type": "zeek.ssl",
        "asset": {"asset_id": "host-web-01"},
        "payload": {
            "event_type": "zeek.ssl",
            "uid": "C123",
            "ts": 1720000000.2,
            "server_name": "api.example.com",
            "ja3": "a0e9f5d64349fb13191bc781f81f42d1",
            "ja4": "t13d1516h2_8daaf6152771_b0da82dd1658",
            "id_orig_h_hash": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "id_resp_h_hash": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "id_orig_p": 54321,
            "id_resp_p": 443,
            "proto": "tcp",
        },
    }
    adapted = zeek_to_flow_event(event)
    flow = normalize_flow(adapted, "salt")
    assert flow["tls"]["sni"] == "api.example.com"
    assert flow["tls"]["ja3"] == "a0e9f5d64349fb13191bc781f81f42d1"
    assert flow["src_ip_hash"] == "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    assert flow["zeek_uid"] == "C123"
