"""Map raw AWS VPC Flow Log (default format v2) lines into flow-shaped envelopes.

Collector side (`detection/collectors/network/aws_vpc_flow_logs.toml`) ships each
flow-log line mostly unparsed (`payload.raw_line`) so the heavy parsing — and its
test coverage — lives here, mirroring the zeek/dns adapters.

Default log format (space-delimited, one record per line):
    version account-id interface-id srcaddr dstaddr srcport dstport protocol
    packets bytes start end action log-status
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from flow_processor.adapters_common import PROTOCOL_BY_NUMBER, extract_payload, iso_from_epoch

_FIELD_COUNT = 14


def is_aws_flow_event(event: dict[str, Any]) -> bool:
    et = str(event.get("event_type") or "")
    if et == "aws.vpc_flow_log":
        return True
    body = extract_payload(event)
    return str(body.get("event_type") or "") == "aws.vpc_flow_log"


def _parse_line(line: str) -> dict[str, Any] | None:
    line = line.strip()
    if not line or line.lower().startswith("version"):
        return None
    fields = line.split(" ")
    if len(fields) < _FIELD_COUNT:
        return None
    (
        _version,
        account_id,
        interface_id,
        srcaddr,
        dstaddr,
        srcport,
        dstport,
        protocol,
        packets,
        num_bytes,
        start,
        _end,
        action,
        _log_status,
    ) = fields[:_FIELD_COUNT]

    if srcaddr in ("-", "") or dstaddr in ("-", ""):
        return None

    try:
        proto_num = int(protocol)
    except ValueError:
        proto_num = -1
    action_l = action.strip().lower()
    if action_l == "accept":
        conn_state = "established"
    elif action_l == "reject":
        conn_state = "rejected"
    else:
        conn_state = "unknown"

    try:
        start_epoch = int(start)
    except ValueError:
        start_epoch = int(datetime.now(tz=timezone.utc).timestamp())

    return {
        "account_id": account_id,
        "interface_id": interface_id,
        "src_ip": srcaddr,
        "dst_ip": dstaddr,
        "src_port": int(srcport) if srcport.isdigit() else None,
        "dst_port": int(dstport) if dstport.isdigit() else None,
        "protocol": PROTOCOL_BY_NUMBER.get(proto_num, "ip"),
        "packets": int(packets) if packets.isdigit() else 0,
        "bytes": int(num_bytes) if num_bytes.isdigit() else 0,
        "connection_state": conn_state,
        "timestamp": start_epoch,
    }


def aws_flow_to_flow_event(event: dict[str, Any]) -> dict[str, Any]:
    """Convert a raw AWS VPC Flow Log envelope into a network.flow-shaped event."""
    body = extract_payload(event)
    raw_line = body.get("raw_line") or body.get("message") or ""
    parsed = _parse_line(str(raw_line))
    if parsed is None:
        raise ValueError(f"unparseable AWS VPC flow log line: {raw_line!r}")

    asset = event.get("asset") if isinstance(event.get("asset"), dict) else {}
    asset_id = event.get("asset_id") or body.get("asset_id") or asset.get("asset_id") or "unknown"
    tenant_id = event.get("tenant_id") or body.get("tenant_id") or "default"
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
        "aws_interface_id": parsed["interface_id"],
        "aws_account_id": parsed["account_id"],
    }

    return {
        "schema_version": event.get("schema_version") or "1.0",
        "event_type": "network.flow",
        "tenant_id": tenant_id,
        "occurred_at": occurred_iso,
        "asset": {"asset_id": asset_id},
        "labels": event.get("labels") or {},
        "payload": payload,
        "cloud_source": "aws_vpc_flow_log",
    }
