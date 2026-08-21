"""Map raw Azure NSG Flow Log (v2 JSON) blobs into flow-shaped envelopes.

Azure NSG Flow Logs v2 records nest many individual flow tuples per blob:
    records[].properties.flows[].flows[].flowTuples[]
where each flowTuple is a CSV string:
    timestamp,srcIp,destIp,srcPort,destPort,protocol,direction,action,state,
    packetsSrcToDst,bytesSrcToDst,packetsDstToSrc,bytesDstToSrc  (state/last-4 v2 only)

One raw NSG blob therefore fans out into many flow events — unlike the
1:1 aws/zeek/dns adapters, this one returns a list.

Collector side (`detection/collectors/network/azure_nsg_flow_logs.toml`) ships
the raw NSG JSON blob mostly unparsed under `payload.nsg_blob`; parsing/tests
live here.
"""

from __future__ import annotations

from typing import Any

from flow_processor.adapters_common import extract_payload, iso_from_epoch

# Azure flowTuples encode protocol as a letter, not an IANA number.
_PROTOCOL_NAMES = {"t": "tcp", "u": "udp"}


def is_azure_flow_event(event: dict[str, Any]) -> bool:
    et = str(event.get("event_type") or "")
    if et == "azure.nsg_flow_log":
        return True
    body = extract_payload(event)
    return str(body.get("event_type") or "") == "azure.nsg_flow_log"


def _parse_tuple(tuple_str: str) -> dict[str, Any] | None:
    parts = str(tuple_str).split(",")
    # v1 tuples have 8 fields (through trafficDecision); v2 adds flowState +
    # per-direction packet/byte counters. Only parts[0..7] are mandatory here.
    if len(parts) < 8:
        return None
    try:
        timestamp = int(parts[0])
    except ValueError:
        return None
    src_ip, dst_ip, src_port, dst_port = parts[1], parts[2], parts[3], parts[4]
    protocol = _PROTOCOL_NAMES.get(parts[5].strip().lower(), "ip")
    action = parts[7].strip().lower()
    conn_state = "established" if action == "a" else "rejected" if action == "d" else "unknown"

    packets = 0
    num_bytes = 0
    # v2 adds src->dst and dst->src packet/byte counters; v1 stops at `state`.
    if len(parts) >= 13:
        packets = (int(parts[9]) if parts[9].isdigit() else 0) + (
            int(parts[11]) if parts[11].isdigit() else 0
        )
        num_bytes = (int(parts[10]) if parts[10].isdigit() else 0) + (
            int(parts[12]) if parts[12].isdigit() else 0
        )

    return {
        "timestamp": timestamp,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": int(src_port) if src_port.isdigit() else None,
        "dst_port": int(dst_port) if dst_port.isdigit() else None,
        "protocol": protocol,
        "connection_state": conn_state,
        "packets": packets,
        "bytes": num_bytes,
    }


def azure_flow_to_flow_events(event: dict[str, Any]) -> list[dict[str, Any]]:
    """Fan out one raw NSG Flow Log blob into one network.flow-shaped event per tuple."""
    body = extract_payload(event)
    blob = body.get("nsg_blob") if isinstance(body.get("nsg_blob"), dict) else body

    asset = event.get("asset") if isinstance(event.get("asset"), dict) else {}
    asset_id = event.get("asset_id") or body.get("asset_id") or asset.get("asset_id") or "unknown"
    tenant_id = event.get("tenant_id") or body.get("tenant_id") or "default"
    schema_version = event.get("schema_version") or "1.0"
    labels = event.get("labels") or {}

    events: list[dict[str, Any]] = []
    records = blob.get("records") if isinstance(blob.get("records"), list) else []
    for record in records:
        if not isinstance(record, dict):
            continue
        resource_id = record.get("resourceId") or ""
        properties = record.get("properties") if isinstance(record.get("properties"), dict) else {}
        rule_groups = properties.get("flows") if isinstance(properties.get("flows"), list) else []
        for rule_group in rule_groups:
            if not isinstance(rule_group, dict):
                continue
            mac_flows = rule_group.get("flows") if isinstance(rule_group.get("flows"), list) else []
            for mac_flow in mac_flows:
                if not isinstance(mac_flow, dict):
                    continue
                tuples = mac_flow.get("flowTuples") if isinstance(mac_flow.get("flowTuples"), list) else []
                for tuple_str in tuples:
                    parsed = _parse_tuple(tuple_str)
                    if parsed is None:
                        continue
                    occurred_iso = iso_from_epoch(parsed["timestamp"])
                    payload = {
                        "event_type": "network.flow",
                        "asset_id": asset_id,
                        "src_ip": parsed["src_ip"],
                        "dst_ip": parsed["dst_ip"],
                        "src_port": parsed["src_port"],
                        "dst_port": parsed["dst_port"],
                        "protocol": parsed["protocol"],
                        "bytes": parsed["bytes"],
                        "packets": parsed["packets"],
                        "connection_state": parsed["connection_state"],
                        "timestamp": occurred_iso,
                        "azure_nsg_resource_id": resource_id,
                        "azure_rule": rule_group.get("rule"),
                    }
                    events.append(
                        {
                            "schema_version": schema_version,
                            "event_type": "network.flow",
                            "tenant_id": tenant_id,
                            "occurred_at": occurred_iso,
                            "asset": {"asset_id": asset_id},
                            "labels": labels,
                            "payload": payload,
                            "cloud_source": "azure_nsg_flow_log",
                        }
                    )
    return events
