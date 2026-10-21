from __future__ import annotations

from flow_processor.dns_adapter import dns_to_flow_event, is_dns_event
from flow_processor.pipeline import FlowPipeline


def test_is_dns_event() -> None:
    assert is_dns_event({"event_type": "dns.query", "payload": {"query": "a.example"}})
    assert is_dns_event({"payload": {"event_type": "dns.query", "query": "b.example"}})
    assert not is_dns_event({"event_type": "network.flow", "payload": {"protocol": "tcp"}})


def test_dns_to_flow_and_pipeline_detectors() -> None:
    event = {
        "event_type": "dns.query",
        "tenant_id": "tenant-acme",
        "asset": {"asset_id": "host-1"},
        "payload": {
            "query": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.evil.example",
            "qtype": "TXT",
            "entropy": 4.5,
            "query_length": 48,
            "src_ip_hash": "sha256:client",
        },
    }
    flow_shaped = dns_to_flow_event(event)
    assert flow_shaped["payload"]["dns"]["query"].startswith("aaaa")
    pipe = FlowPipeline()
    # Need enough events for a window
    batch = []
    for i in range(8):
        batch.append(
            {
                **event,
                "occurred_at": f"2026-07-27T14:00:0{i}Z",
                "payload": {
                    **event["payload"],
                    "query": ("a" * 40) + f".{i}.tunnel.example",
                    "entropy": 4.2,
                    "query_length": 55,
                },
            }
        )
    features = pipe.process_events(batch)
    assert isinstance(features, list)
