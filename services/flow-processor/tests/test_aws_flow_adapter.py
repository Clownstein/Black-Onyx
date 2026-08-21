from flow_processor.aws_flow_adapter import aws_flow_to_flow_event, is_aws_flow_event
from flow_processor.normalize import normalize_flow

_ACCEPT_LINE = "2 123456789010 eni-1235b8ca 10.0.1.5 10.0.0.220 20641 22 6 20 4249 1418530010 1418530070 ACCEPT OK"
_REJECT_LINE = "2 123456789010 eni-1235b8ca 172.31.9.69 172.31.9.12 49761 3389 6 20 4249 1418530010 1418530070 REJECT OK"


def _event(raw_line: str) -> dict:
    return {
        "event_type": "aws.vpc_flow_log",
        "tenant_id": "t1",
        "asset": {"asset_id": "vpc-eni-1235b8ca"},
        "payload": {"raw_line": raw_line},
    }


def test_is_aws_flow_event():
    assert is_aws_flow_event(_event(_ACCEPT_LINE)) is True
    assert is_aws_flow_event({"event_type": "zeek.conn"}) is False


def test_aws_flow_to_flow_event_parses_accept():
    flow_event = aws_flow_to_flow_event(_event(_ACCEPT_LINE))
    assert flow_event["payload"]["src_ip"] == "10.0.1.5"
    assert flow_event["payload"]["dst_ip"] == "10.0.0.220"
    assert flow_event["payload"]["dst_port"] == 22
    assert flow_event["payload"]["protocol"] == "tcp"
    assert flow_event["payload"]["connection_state"] == "established"
    assert flow_event["payload"]["bytes"] == 4249
    assert flow_event["payload"]["packets"] == 20
    assert flow_event["occurred_at"] == "2014-12-14T04:06:50Z"


def test_aws_flow_to_flow_event_parses_reject():
    flow_event = aws_flow_to_flow_event(_event(_REJECT_LINE))
    assert flow_event["payload"]["connection_state"] == "rejected"


def test_aws_flow_to_flow_event_skips_header_line():
    header = "version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status"
    try:
        aws_flow_to_flow_event(_event(header))
        assert False, "expected ValueError for header line"
    except ValueError:
        pass


def test_aws_flow_event_normalizes_end_to_end():
    flow_event = aws_flow_to_flow_event(_event(_ACCEPT_LINE))
    flow = normalize_flow(flow_event, "salt")
    assert flow["protocol"] == "tcp"
    assert flow["dst_port"] == 22
    assert flow["direction"] in {"east_west", "egress", "ingress", "external"}
