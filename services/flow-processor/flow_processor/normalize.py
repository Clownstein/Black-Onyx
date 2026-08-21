from __future__ import annotations

import hashlib
import math
from datetime import datetime, timezone
from typing import Any


def hash_ip(ip: str, salt: str) -> str:
    """SHA-256 hash of salted IP for privacy-preserving peer identity."""
    digest = hashlib.sha256(f"{salt}:{ip.strip().lower()}".encode("utf-8")).hexdigest()
    return digest[:32]


def _parse_ts(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
    if isinstance(value, (int, float)):
        # seconds or ms
        ts = float(value)
        if ts > 1e12:
            ts /= 1000.0
        return datetime.fromtimestamp(ts, tz=timezone.utc)
    if isinstance(value, str):
        text = value.strip().replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            return None
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    return None


def is_private_or_internal(ip: str) -> bool:
    ip = ip.strip().lower()
    if ip in {"localhost", "::1"}:
        return True
    if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("127."):
        return True
    if ip.startswith("172."):
        parts = ip.split(".")
        if len(parts) >= 2 and parts[1].isdigit() and 16 <= int(parts[1]) <= 31:
            return True
    return False


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _extract_tls(payload: dict[str, Any]) -> dict[str, Any] | None:
    tls = payload.get("tls")
    if not isinstance(tls, dict):
        tls = {}
    sni = (
        tls.get("sni")
        or tls.get("server_name")
        or payload.get("sni")
        or payload.get("server_name")
    )
    ja3 = tls.get("ja3") or payload.get("ja3")
    ja3s = tls.get("ja3s") or payload.get("ja3s")
    ja4 = tls.get("ja4") or payload.get("ja4")
    version = tls.get("version") or payload.get("tls_version")
    cipher = tls.get("cipher") or payload.get("cipher")
    if not any([sni, ja3, ja3s, ja4, version, cipher]):
        return None
    out: dict[str, Any] = {}
    if sni:
        out["sni"] = str(sni).lower()
    if ja3:
        out["ja3"] = str(ja3).lower()
    if ja3s:
        out["ja3s"] = str(ja3s).lower()
    if ja4:
        out["ja4"] = str(ja4).lower()
    if version:
        out["version"] = str(version)
    if cipher:
        out["cipher"] = str(cipher)
    return out


def _extract_dns(payload: dict[str, Any]) -> dict[str, Any] | None:
    dns = payload.get("dns")
    if not isinstance(dns, dict):
        dns = {}
    query = (
        dns.get("query")
        or dns.get("qname")
        or dns.get("query_name")
        or payload.get("query")
        or payload.get("qname")
        or payload.get("query_name")
    )
    qtype = dns.get("qtype") or dns.get("qtype_name") or payload.get("qtype") or payload.get("query_type")
    rcode = dns.get("rcode") or dns.get("rcode_name") or payload.get("rcode") or payload.get("response_code")
    answers = dns.get("answers") or payload.get("answers") or []
    if isinstance(answers, str):
        answers = [answers]
    query_length = dns.get("query_length")
    if query_length is None and query:
        query_length = len(str(query))
    entropy = dns.get("entropy")
    if entropy is None and query:
        # Entropy of labels excluding dots (tunneling heuristic).
        entropy = round(_shannon_entropy(str(query).replace(".", "")), 4)
    if not any([query, qtype, rcode, answers]):
        return None
    out: dict[str, Any] = {}
    if query:
        out["query"] = str(query).lower()
    if qtype:
        out["qtype"] = str(qtype)
    if rcode:
        out["rcode"] = str(rcode)
    if answers:
        out["answers"] = [str(a) for a in answers]
    if query_length is not None:
        out["query_length"] = int(query_length)
    if entropy is not None:
        out["entropy"] = float(entropy)
    return out


def normalize_flow(event: dict[str, Any], salt: str) -> dict[str, Any]:
    """Map a raw ingest event into the canonical network.flow schema."""
    payload = event.get("payload") or event.get("extensions") or event
    if not isinstance(payload, dict):
        payload = event

    src_ip = str(payload.get("src_ip") or payload.get("source_ip") or "")
    dst_ip = str(payload.get("dst_ip") or payload.get("destination_ip") or "")
    src_hash_pre = payload.get("src_ip_hash") or payload.get("id_orig_h_hash")
    dst_hash_pre = (
        payload.get("dst_ip_hash")
        or payload.get("dest_ip_hash")
        or payload.get("id_resp_h_hash")
    )

    if not src_ip and not src_hash_pre:
        raise ValueError("src_ip and dst_ip are required")
    if not dst_ip and not dst_hash_pre:
        raise ValueError("src_ip and dst_ip are required")

    occurred = _parse_ts(event.get("occurred_at") or payload.get("timestamp") or payload.get("ts"))
    if occurred is None:
        raise ValueError("occurred_at/timestamp required")

    dst_port = int(
        payload.get("dst_port")
        or payload.get("destination_port")
        or payload.get("dest_port")
        or payload.get("id_resp_p")
        or 0
    )
    src_port = int(
        payload.get("src_port")
        or payload.get("source_port")
        or payload.get("id_orig_p")
        or 0
    )
    protocol = str(payload.get("protocol") or payload.get("proto") or "tcp").lower()
    bytes_total = int(
        payload.get("bytes")
        or payload.get("bytes_total")
        or (
            int(payload.get("orig_bytes") or 0) + int(payload.get("resp_bytes") or 0)
        )
        or 0
    )
    packets = int(
        payload.get("packets")
        or (
            int(payload.get("orig_pkts") or 0) + int(payload.get("resp_pkts") or 0)
        )
        or 0
    )
    conn_state = str(
        payload.get("connection_state") or payload.get("conn_state") or payload.get("state") or "unknown"
    ).lower()
    failed = bool(
        payload.get("failed")
        or conn_state in {"failed", "rejected", "reset", "timeout", "s0", "rej"}
    )

    asset = event.get("asset") or {}
    asset_id = str(asset.get("asset_id") or payload.get("asset_id") or event.get("asset_id") or "unknown")
    tenant_id = str(event.get("tenant_id") or "default")

    if src_ip:
        src_internal = is_private_or_internal(src_ip)
        src_ip_hash = hash_ip(src_ip, salt)
    else:
        src_ip_hash = str(src_hash_pre)
        # Pre-hashed Zeek records: treat as internal unless zone says otherwise.
        src_internal = str(payload.get("src_zone") or "internal").lower() != "external"

    if dst_ip:
        dst_internal = is_private_or_internal(dst_ip)
        dst_ip_hash = hash_ip(dst_ip, salt)
    else:
        dst_ip_hash = str(dst_hash_pre)
        dst_internal = str(payload.get("dst_zone") or "external").lower() == "internal"

    if src_internal and not dst_internal:
        direction = "egress"
    elif not src_internal and dst_internal:
        direction = "ingress"
    elif src_internal and dst_internal:
        direction = "east_west"
    else:
        direction = "external"

    peer_hash = dst_ip_hash if direction == "egress" else src_ip_hash

    flow: dict[str, Any] = {
        "schema_version": "1.0",
        "event_type": "network.flow",
        "tenant_id": tenant_id,
        "asset_id": asset_id,
        "occurred_at": occurred.isoformat().replace("+00:00", "Z"),
        "src_ip_hash": src_ip_hash,
        "dst_ip_hash": dst_ip_hash,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "bytes": bytes_total,
        "packets": packets,
        "connection_state": conn_state,
        "failed": failed,
        "direction": direction,
        "dst_is_external": not dst_internal,
        "src_is_external": not src_internal,
        "peer_hash": peer_hash,
        "labels": event.get("labels") or {},
    }

    tls = _extract_tls(payload)
    if tls:
        flow["tls"] = tls
    dns = _extract_dns(payload)
    if dns:
        flow["dns"] = dns

    for key in ("zeek_uid", "uid", "community_id", "flow_id", "sensor_id", "service"):
        val = payload.get(key) or event.get(key)
        if val is not None and key not in flow:
            # Normalize uid → zeek_uid
            out_key = "zeek_uid" if key == "uid" else key
            flow[out_key] = val

    return flow
