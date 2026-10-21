from flow_processor.gcp_flow_adapter import gcp_flow_to_flow_event, is_gcp_flow_event
from flow_processor.normalize import normalize_flow

_LOG_ENTRY = {
    "timestamp": "2024-01-01T00:00:05.000000000Z",
    "resource": {"labels": {"instance_id": "gce-web-01"}},
    "jsonPayload": {
        "connection": {
            "src_ip": "10.128.0.5",
            "dest_ip": "10.128.0.9",
            "src_port": 51820,
            "dest_port": 443,
            "protocol": 6,
        },
        "bytes_sent": "1500",
        "packets_sent": "12",
        "start_time": "2024-01-01T00:00:00.000000000Z",
        "reporter": "SRC",
    },
}


def _event() -> dict:
    return {
        "event_type": "gcp.vpc_flow_log",
        "tenant_id": "t1",
        "payload": {"log_entry": _LOG_ENTRY},
    }


def test_is_gcp_flow_event():
    assert is_gcp_flow_event(_event()) is True
    assert is_gcp_flow_event({"event_type": "zeek.conn"}) is False


def test_gcp_flow_to_flow_event_parses_connection():
    flow_event = gcp_flow_to_flow_event(_event())
    assert flow_event["payload"]["src_ip"] == "10.128.0.5"
    assert flow_event["payload"]["dst_ip"] == "10.128.0.9"
    assert flow_event["payload"]["dst_port"] == 443
    assert flow_event["payload"]["protocol"] == "tcp"
    assert flow_event["payload"]["bytes"] == 1500
    assert flow_event["payload"]["packets"] == 12
    assert flow_event["occurred_at"] == "2024-01-01T00:00:00Z"
    assert flow_event["asset"]["asset_id"] == "gce-web-01"


def test_gcp_flow_to_flow_event_requires_connection():
    try:
        gcp_flow_to_flow_event({"event_type": "gcp.vpc_flow_log", "payload": {"log_entry": {}}})
        assert False, "expected ValueError for missing connection"
    except ValueError:
        pass


def test_gcp_flow_event_normalizes_end_to_end():
    flow_event = gcp_flow_to_flow_event(_event())
    flow = normalize_flow(flow_event, "salt")
    assert flow["protocol"] == "tcp"
    assert flow["dst_port"] == 443
