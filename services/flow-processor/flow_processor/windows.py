from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any


def _ts(flow: dict[str, Any]) -> datetime:
    return datetime.fromisoformat(flow["occurred_at"].replace("Z", "+00:00")).replace(tzinfo=None)


def build_windows(
    flows: list[dict[str, Any]],
    *,
    duration_seconds: int = 300,
    max_events: int = 256,
    stride_events: int = 64,
    minimum_events: int = 4,
) -> list[dict[str, Any]]:
    """Build overlapping event windows (max 256, stride 64, min 4) within 5m spans."""
    if not flows:
        return []

    ordered = sorted(flows, key=_ts)
    windows: list[dict[str, Any]] = []
    n = len(ordered)
    start = 0
    while start < n:
        anchor = _ts(ordered[start])
        end_bound = anchor + timedelta(seconds=duration_seconds)
        chunk: list[dict[str, Any]] = []
        idx = start
        while idx < n and len(chunk) < max_events:
            flow = ordered[idx]
            if _ts(flow) > end_bound:
                break
            chunk.append(flow)
            idx += 1

        if len(chunk) >= minimum_events:
            asset_id = chunk[0].get("asset_id", "unknown")
            tenant_id = chunk[0].get("tenant_id", "default")
            windows.append(
                {
                    "schema_version": "1.0",
                    "event_type": "network.features",
                    "tenant_id": tenant_id,
                    "asset_id": asset_id,
                    "window_start": _ts(chunk[0]).isoformat(),
                    "window_end": _ts(chunk[-1]).isoformat(),
                    "event_count": len(chunk),
                    "flows": chunk,
                    "aggregates": aggregate_window(chunk),
                }
            )

        if start + stride_events >= n:
            break
        start += stride_events

    return windows


def aggregate_window(flows: list[dict[str, Any]]) -> dict[str, Any]:
    peers = {f["peer_hash"] for f in flows}
    ports = {f["dst_port"] for f in flows}
    failed = sum(1 for f in flows if f.get("failed"))
    external_peers = {f["peer_hash"] for f in flows if f.get("dst_is_external") or f.get("src_is_external")}
    ja3 = {
        str(f["tls"]["ja3"])
        for f in flows
        if isinstance(f.get("tls"), dict) and f["tls"].get("ja3")
    }
    ja4 = {
        str(f["tls"]["ja4"])
        for f in flows
        if isinstance(f.get("tls"), dict) and f["tls"].get("ja4")
    }
    sni = {
        str(f["tls"]["sni"])
        for f in flows
        if isinstance(f.get("tls"), dict) and f["tls"].get("sni")
    }
    dns_queries = [
        f["dns"]
        for f in flows
        if isinstance(f.get("dns"), dict) and f["dns"].get("query")
    ]
    return {
        "distinct_peers": len(peers),
        "distinct_dst_ports": len(ports),
        "failed_connections": failed,
        "external_peers": len(external_peers),
        "bytes_total": sum(int(f.get("bytes") or 0) for f in flows),
        "packets_total": sum(int(f.get("packets") or 0) for f in flows),
        "protocols": sorted({str(f.get("protocol")) for f in flows}),
        "distinct_ja3": len(ja3),
        "distinct_ja4": len(ja4),
        "distinct_sni": len(sni),
        "dns_query_count": len(dns_queries),
    }
