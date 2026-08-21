"""Map Zeek conn/dns/ssl events into flow-shaped envelopes for normalize_flow."""

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


def is_zeek_event(event: dict[str, Any]) -> bool:
    et = str(event.get("event_type") or "")
    if et.startswith("zeek."):
        return True
    body = _payload(event)
    bet = str(body.get("event_type") or "")
    return bet.startswith("zeek.")


def zeek_to_flow_event(event: dict[str, Any]) -> dict[str, Any]:
    """Convert a Zeek log envelope into a network.flow-shaped event.

    Prefer calling this from the pipeline when ``event_type`` starts with ``zeek.``.
    Gateway may also publish Zeek JSON to ``zeek.raw``; flow-processor can consume
    those envelopes via this adapter (or a separate consumer wired to ``zeek.raw``).
    """
    body = _payload(event)
    event_type = str(body.get("event_type") or event.get("event_type") or "zeek.conn")

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

    payload: dict[str, Any] = {
        "event_type": "network.flow",
        "asset_id": asset_id,
        "src_ip": body.get("src_ip") or body.get("id.orig_h") or body.get("id_orig_h"),
        "dst_ip": body.get("dst_ip")
        or body.get("id.resp_h")
        or body.get("id_resp_h"),
        "src_ip_hash": body.get("src_ip_hash") or body.get("id_orig_h_hash"),
        "dst_ip_hash": body.get("dst_ip_hash")
        or body.get("dest_ip_hash")
        or body.get("id_resp_h_hash"),
        "src_port": body.get("src_port") or body.get("id.orig_p") or body.get("id_orig_p"),
        "dst_port": body.get("dst_port")
        or body.get("id.resp_p")
        or body.get("id_resp_p"),
        "protocol": body.get("protocol") or body.get("proto") or "tcp",
        "bytes": body.get("bytes")
        or (
            int(body.get("orig_bytes") or 0) + int(body.get("resp_bytes") or 0)
        ),
        "packets": body.get("packets")
        or (
            int(body.get("orig_pkts") or 0) + int(body.get("resp_pkts") or 0)
        ),
        "connection_state": body.get("connection_state")
        or body.get("conn_state")
        or body.get("state"),
        "uid": body.get("uid"),
        "zeek_uid": body.get("uid") or body.get("zeek_uid"),
        "community_id": body.get("community_id"),
        "sensor_id": body.get("sensor_id"),
        "service": body.get("service"),
        "timestamp": occurred,
    }

    if event_type in {"zeek.ssl", "zeek.tls"} or any(
        body.get(k) for k in ("ja3", "ja4", "server_name", "sni")
    ):
        payload["tls"] = {
            "sni": body.get("server_name") or body.get("sni"),
            "ja3": body.get("ja3"),
            "ja3s": body.get("ja3s"),
            "ja4": body.get("ja4"),
            "version": body.get("version"),
            "cipher": body.get("cipher"),
        }

    if event_type == "zeek.dns" or body.get("query") or body.get("qtype_name"):
        payload["dns"] = {
            "query": body.get("query"),
            "qtype": body.get("qtype_name") or body.get("qtype"),
            "rcode": body.get("rcode_name") or body.get("rcode"),
            "answers": body.get("answers") or [],
            "query_length": body.get("query_length"),
            "entropy": body.get("entropy"),
        }
        # DNS-only rows may lack resp host; use placeholder external peer hash.
        if not payload.get("dst_ip") and not payload.get("dst_ip_hash"):
            payload["dst_ip_hash"] = "dns-query-peer"
            payload["dst_zone"] = "external"
        if not payload.get("src_ip") and not payload.get("src_ip_hash"):
            payload["src_ip_hash"] = body.get("id_orig_h_hash") or "dns-client"
            payload["src_zone"] = "internal"
        payload["protocol"] = "udp"
        payload["dst_port"] = payload.get("dst_port") or 53

    # Drop empty nested objects
    if isinstance(payload.get("tls"), dict) and not any(payload["tls"].values()):
        del payload["tls"]
    if isinstance(payload.get("dns"), dict) and not any(
        v not in (None, [], "") for v in payload["dns"].values()
    ):
        del payload["dns"]

    return {
        "schema_version": event.get("schema_version") or "1.0",
        "event_type": "network.flow",
        "tenant_id": tenant_id,
        "occurred_at": occurred,
        "asset": {"asset_id": asset_id},
        "labels": event.get("labels") or {},
        "payload": payload,
        "zeek_event_type": event_type,
    }
