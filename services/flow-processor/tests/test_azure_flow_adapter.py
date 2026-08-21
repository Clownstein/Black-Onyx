from flow_processor.azure_flow_adapter import azure_flow_to_flow_events, is_azure_flow_event
from flow_processor.normalize import normalize_flow

_NSG_BLOB = {
    "records": [
        {
            "time": "2020-04-26T15:00:35.0000000Z",
            "resourceId": "/SUBSCRIPTIONS/x/RESOURCEGROUPS/y/PROVIDERS/MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/NSG1",
            "properties": {
                "Version": 2,
                "flows": [
                    {
                        "rule": "UserRule_default-allow-ssh",
                        "flows": [
                            {
                                "mac": "000D3AABBCC",
                                "flowTuples": [
                                    "1587913235,10.0.0.4,10.0.0.5,52033,22,T,I,A,B,10,1155,8,660",
                                    "1587913240,10.0.0.4,10.0.0.6,52099,3389,T,I,D,B,1,60,0,0",
                                ],
                            }
                        ],
                    }
                ],
            },
        }
    ]
}


def _event() -> dict:
    return {
        "event_type": "azure.nsg_flow_log",
        "tenant_id": "t1",
        "payload": {"nsg_blob": _NSG_BLOB, "asset_id": "nsg-host-01"},
    }


def test_is_azure_flow_event():
    assert is_azure_flow_event(_event()) is True
    assert is_azure_flow_event({"event_type": "zeek.conn"}) is False


def test_azure_flow_fans_out_flow_tuples():
    events = azure_flow_to_flow_events(_event())
    assert len(events) == 2

    allowed = events[0]["payload"]
    assert allowed["src_ip"] == "10.0.0.4"
    assert allowed["dst_ip"] == "10.0.0.5"
    assert allowed["dst_port"] == 22
    assert allowed["protocol"] == "tcp"
    assert allowed["connection_state"] == "established"
    assert allowed["packets"] == 18
    assert allowed["bytes"] == 1815
    assert events[0]["occurred_at"] == "2020-04-26T15:00:35Z"

    denied = events[1]["payload"]
    assert denied["dst_port"] == 3389
    assert denied["connection_state"] == "rejected"


def test_azure_flow_parses_v1_eight_field_tuple():
    # v1 flowTuples have 8 fields (through trafficDecision) and no byte/packet
    # counters. Regression: the min-length guard used to reject these.
    v1_blob = {
        "records": [
            {
                "resourceId": "/SUBSCRIPTIONS/x/NETWORKSECURITYGROUPS/NSG1",
                "properties": {
                    "flows": [
                        {
                            "rule": "UserRule_allow-https",
                            "flows": [
                                {"mac": "000D3AABBCC", "flowTuples": ["1587913235,10.0.0.4,10.0.0.5,52033,443,T,O,A"]}
                            ],
                        }
                    ]
                },
            }
        ]
    }
    events = azure_flow_to_flow_events(
        {"event_type": "azure.nsg_flow_log", "tenant_id": "t1", "payload": {"nsg_blob": v1_blob}}
    )
    assert len(events) == 1
    payload = events[0]["payload"]
    assert payload["dst_port"] == 443
    assert payload["connection_state"] == "established"
    assert payload["packets"] == 0
    assert payload["bytes"] == 0


def test_azure_flow_event_normalizes_end_to_end():
    events = azure_flow_to_flow_events(_event())
    flows = [normalize_flow(e, "salt") for e in events]
    assert len(flows) == 2
    assert flows[0]["protocol"] == "tcp"
