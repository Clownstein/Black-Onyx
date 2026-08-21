"""Map raw GCP VPC Flow Log (Cloud Logging) entries into flow-shaped envelopes.

GCP VPC Flow Logs are exported via Cloud Logging, typically forwarded to Pub/Sub.
Each message is a LogEntry JSON with a `jsonPayload.connection` block:
    {"src_ip", "dest_ip", "src_port", "dest_port", "protocol"} + bytes_sent/
    packets_sent + start_time/end_time (RFC3339).

Collector side (`detection/collectors/network/gcp_vpc_flow_logs.toml`) ships the
LogEntry mostly unparsed under `payload.log_entry`; parsing/tests live here,
mirroring the aws/zeek/dns adapters.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from flow_processor.adapters_common import PROTOCOL_BY_NUMBER, extract_payload


def is_gcp_flow_event(event: dict[str, Any]) -> bool:
    et = str(event.get("event_type") or "")
    if et == "gcp.vpc_flow_log":
        return True
    body = extract_payload(event)
    return str(body.get("event_type") or "") == "gcp.vpc_flow_log"


def _parse_rfc3339(value: Any) -> tuple[int, str]:
    """Return (epoch_seconds, iso_z) for an RFC3339 timestamp, falling back to now."""
    if isinstance(value, str) and value.strip():
        text = value.strip().replace("Z", "+00:00")
        try:
            dt = datetime.fromisoformat(text)
        except ValueError:
            dt = datetime.now(tz=timezone.utc)
    else:
        dt = datetime.now(tz=timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    dt = dt.astimezone(timezone.utc)
    return int(dt.timestamp()), dt.isoformat().replace("+00:00", "Z")


def gcp_flow_to_flow_event(event: dict[str, Any]) -> dict[str, Any]:
    """Convert a raw GCP VPC Flow Log LogEntry envelope into a network.flow-shaped event."""
    body = extract_payload(event)
    log_entry = body.get("log_entry") if isinstance(body.get("log_entry"), dict) else body
    json_payload = (
        log_entry.get("jsonPayload") if isinstance(log_entry.get("jsonPayload"), dict) else log_entry
    )
    connection = json_payload.get("connection") if isinstance(json_payload.get("connection"), dict) else {}

    src_ip = connection.get("src_ip")
    dst_ip = connection.get("dest_ip")
    if not src_ip or not dst_ip:
        raise ValueError("GCP VPC flow log entry missing connection.src_ip/dest_ip")

    try:
        proto_num = int(connection.get("protocol"))
    except (TypeError, ValueError):
        proto_num = -1
    protocol = PROTOCOL_BY_NUMBER.get(proto_num, "ip")

    _start_epoch, occurred_iso = _parse_rfc3339(
        json_payload.get("start_time") or log_entry.get("timestamp")
    )

    asset = event.get("asset") if isinstance(event.get("asset"), dict) else {}
    asset_id = (
        event.get("asset_id")
        or body.get("asset_id")
        or asset.get("asset_id")
        or (log_entry.get("resource") or {}).get("labels", {}).get("instance_id")
        or "unknown"
    )
    tenant_id = event.get("tenant_id") or body.get("tenant_id") or "default"

    def _num(value: Any) -> int:
        try:
            return int(value)
        except (TypeError, ValueError):
            return 0

    payload = {
        "event_type": "network.flow",
        "asset_id": asset_id,
        "src_ip": str(src_ip),
        "dst_ip": str(dst_ip),
        "src_port": _num(connection.get("src_port")) or None,
        "dst_port": _num(connection.get("dest_port")) or None,
        "protocol": protocol,
        "bytes": _num(json_payload.get("bytes_sent")),
        "packets": _num(json_payload.get("packets_sent")),
        "connection_state": "established",
        "timestamp": occurred_iso,
        "gcp_reporter": json_payload.get("reporter"),
    }

    return {
        "schema_version": event.get("schema_version") or "1.0",
        "event_type": "network.flow",
        "tenant_id": tenant_id,
        "occurred_at": occurred_iso,
        "asset": {"asset_id": asset_id},
        "labels": event.get("labels") or {},
        "payload": payload,
        "cloud_source": "gcp_vpc_flow_log",
    }
