"""Map standalone dns.query / dns.raw envelopes into flow-shaped events."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from flow_processor.adapters_common import extract_payload as _payload


def _ts_to_iso(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        dt = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    if isinstance(value, (int, float)):
        ts = float(value)
        if ts > 1e12:
            ts /= 1000.0
        return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat().replace("+00:00", "Z")
    if isinstance(value, str) and value.strip():
        return value
    return None


def is_dns_event(event: dict[str, Any]) -> bool:
    et = str(event.get("event_type") or "")
    if et in {"dns.query", "dns.raw", "dns"} or et.startswith("dns."):
        return True
    body = _payload(event)
    bet = str(body.get("event_type") or "")
    if bet in {"dns.query", "dns.raw", "dns"} or bet.startswith("dns."):
        return True
    return bool(body.get("query") or body.get("qname")) and not str(
        body.get("event_type") or ""
    ).startswith("zeek.")


def dns_to_flow_event(event: dict[str, Any]) -> dict[str, Any]:
    """Convert a DNS ingest envelope into a network.flow-shaped event with dns{}."""
    body = _payload(event)
    asset = event.get("asset") if isinstance(event.get("asset"), dict) else {}
    asset_id = (
        event.get("asset_id")
        or body.get("asset_id")
        or asset.get("asset_id")
        or "unknown"
    )
    tenant_id = event.get("tenant_id") or body.get("tenant_id") or "default"
    occurred = (
        _ts_to_iso(event.get("occurred_at"))
        or _ts_to_iso(body.get("ts"))
        or _ts_to_iso(body.get("timestamp"))
    )
    query = body.get("query") or body.get("qname") or body.get("name") or ""
    query_s = str(query)
    entropy = body.get("entropy")
    if entropy is None and query_s:
        # Shannon-ish length proxy used by dns tunneling detector.
        entropy = min(8.0, len(set(query_s.lower())) / max(len(query_s), 1) * 8.0)

    payload: dict[str, Any] = {
        "event_type": "network.flow",
        "asset_id": asset_id,
        "src_ip_hash": body.get("src_ip_hash")
        or body.get("id_orig_h_hash")
        or body.get("client_ip_hash")
        or "dns-client",
        "dst_ip_hash": body.get("dst_ip_hash")
        or body.get("id_resp_h_hash")
        or body.get("resolver_ip_hash")
        or "dns-resolver",
        "src_port": body.get("src_port") or body.get("id_orig_p"),
        "dst_port": body.get("dst_port") or body.get("id_resp_p") or 53,
        "protocol": body.get("protocol") or body.get("proto") or "udp",
        "bytes": body.get("bytes") or max(len(query_s), 1),
        "packets": body.get("packets") or 1,
        "zeek_uid": body.get("uid") or body.get("zeek_uid"),
        "community_id": body.get("community_id"),
        "sensor_id": body.get("sensor_id"),
        "timestamp": occurred,
        "dns": {
            "query": query_s,
            "qtype": body.get("qtype") or body.get("qtype_name"),
            "rcode": body.get("rcode") or body.get("rcode_name"),
            "answers": body.get("answers") or [],
            "query_length": body.get("query_length") or len(query_s),
            "entropy": entropy,
        },
    }

    return {
        "schema_version": event.get("schema_version") or "1.0",
        "event_type": "network.flow",
        "tenant_id": tenant_id,
        "occurred_at": occurred,
        "asset": {"asset_id": asset_id},
        "labels": event.get("labels") or {},
        "payload": payload,
        "dns_event_type": str(body.get("event_type") or event.get("event_type") or "dns.query"),
    }
