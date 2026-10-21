from __future__ import annotations

from datetime import datetime
from statistics import mean, pstdev
from typing import Any


def _parse_ts(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.replace(tzinfo=None) if value.tzinfo else value
    text = str(value).strip()
    if not text:
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).replace(tzinfo=None)
    except ValueError:
        return None


def detect_new_external_peer(
    window: dict[str, Any],
    known_external_peers: set[str] | None = None,
) -> dict[str, Any] | None:
    """Flag peers that are external and not previously observed for the asset."""
    known = known_external_peers or set()
    novel: list[str] = []
    for flow in window.get("flows") or []:
        if not flow.get("dst_is_external"):
            continue
        peer = flow["peer_hash"]
        if peer not in known:
            novel.append(peer)
    novel = sorted(set(novel))
    if not novel:
        return None
    return {
        "detector": "new_external_peer",
        "severity": "medium" if len(novel) == 1 else "high",
        "score": min(1.0, 0.55 + 0.1 * len(novel)),
        "mitre_tactics": ["TA0011"],
        "mitre_techniques": ["T1071"],
        "evidence": {"novel_peers": novel[:16], "count": len(novel)},
    }


def detect_port_scan_heuristic(window: dict[str, Any]) -> dict[str, Any] | None:
    """Many distinct destination ports with low bytes per connection → scan-like."""
    aggregates = window.get("aggregates") or {}
    ports = int(aggregates.get("distinct_dst_ports") or 0)
    peers = int(aggregates.get("distinct_peers") or 0)
    events = int(window.get("event_count") or 0)
    bytes_total = int(aggregates.get("bytes_total") or 0)
    if events < 8 or ports < 10:
        return None
    avg_bytes = bytes_total / max(events, 1)
    # High fan-out on ports from few peers with tiny payloads.
    if ports >= 10 and peers <= 3 and avg_bytes < 200:
        return {
            "detector": "port_scan_heuristic",
            "severity": "high",
            "score": min(0.99, 0.6 + ports / 100.0),
            "mitre_tactics": ["TA0007"],
            "mitre_techniques": ["T1046"],
            "evidence": {
                "distinct_dst_ports": ports,
                "distinct_peers": peers,
                "avg_bytes": round(avg_bytes, 2),
            },
        }
    return None


def detect_failed_connection_burst(window: dict[str, Any]) -> dict[str, Any] | None:
    """Burst of failed connections relative to window size."""
    aggregates = window.get("aggregates") or {}
    failed = int(aggregates.get("failed_connections") or 0)
    events = int(window.get("event_count") or 0)
    if events < 4 or failed < 5:
        return None
    ratio = failed / events
    if failed >= 5 and ratio >= 0.5:
        return {
            "detector": "failed_connection_burst",
            "severity": "high" if ratio >= 0.75 else "medium",
            "score": min(0.99, 0.5 + ratio / 2.0),
            "mitre_tactics": ["TA0007"],
            "mitre_techniques": ["T1046"],
            "evidence": {"failed": failed, "events": events, "ratio": round(ratio, 3)},
        }
    return None


def detect_beaconing_heuristic(window: dict[str, Any]) -> dict[str, Any] | None:
    """Regular-interval connections to the same peer (C2-like beaconing)."""
    by_peer: dict[str, list[datetime]] = {}
    for flow in window.get("flows") or []:
        peer = flow.get("peer_hash")
        if not peer:
            continue
        ts = _parse_ts(flow.get("occurred_at"))
        if ts is None:
            continue
        by_peer.setdefault(str(peer), []).append(ts)

    best: dict[str, Any] | None = None
    for peer, stamps in by_peer.items():
        if len(stamps) < 5:
            continue
        ordered = sorted(stamps)
        intervals = [
            (ordered[i] - ordered[i - 1]).total_seconds() for i in range(1, len(ordered))
        ]
        if not intervals:
            continue
        avg = mean(intervals)
        if avg < 5.0 or avg > 3600.0:
            continue
        spread = pstdev(intervals) if len(intervals) > 1 else 0.0
        cv = spread / avg if avg > 0 else 999.0
        # Low coefficient of variation ⇒ near-periodic reconnects.
        if cv > 0.25:
            continue
        score = min(0.99, 0.55 + (1.0 - cv) * 0.35 + min(len(ordered), 20) / 100.0)
        candidate = {
            "detector": "beaconing_heuristic",
            "severity": "high" if score >= 0.8 else "medium",
            "score": round(score, 4),
            "mitre_tactics": ["TA0011"],
            "mitre_techniques": ["T1071", "T1573"],
            "evidence": {
                "peer_hash": peer,
                "connection_count": len(ordered),
                "mean_interval_seconds": round(avg, 2),
                "interval_cv": round(cv, 4),
                "interval_stdev_seconds": round(spread, 2),
            },
        }
        if best is None or float(candidate["score"]) > float(best["score"]):
            best = candidate
    return best


def detect_cross_host_external_ip(window: dict[str, Any]) -> dict[str, Any] | None:
    """Same external peer contacted by multiple assets in one window.

    Feasible when the window's flows (or ``asset_ids`` metadata) span ≥2 assets.
    Single-asset windows return None.
    """
    flows = list(window.get("flows") or [])
    meta_assets = window.get("asset_ids") or window.get("assets") or []
    asset_ids: set[str] = {str(a) for a in meta_assets if a}
    for flow in flows:
        aid = flow.get("asset_id")
        if aid:
            asset_ids.add(str(aid))
    if len(asset_ids) < 2:
        return None

    peer_assets: dict[str, set[str]] = {}
    for flow in flows:
        if not (flow.get("dst_is_external") or flow.get("src_is_external")):
            continue
        peer = flow.get("peer_hash")
        aid = flow.get("asset_id")
        if not peer or not aid:
            continue
        peer_assets.setdefault(str(peer), set()).add(str(aid))

    multi = {
        peer: sorted(assets)
        for peer, assets in peer_assets.items()
        if len(assets) >= 2
    }
    if not multi:
        return None
    # Prefer the peer spanning the most assets.
    top_peer, assets = max(multi.items(), key=lambda item: len(item[1]))
    score = min(0.99, 0.6 + 0.1 * len(assets))
    return {
        "detector": "cross_host_external_ip",
        "severity": "high" if len(assets) >= 3 else "medium",
        "score": round(score, 4),
        "mitre_tactics": ["TA0011"],
        "mitre_techniques": ["T1071", "T1102"],
        "evidence": {
            "peer_hash": top_peer,
            "asset_ids": assets,
            "asset_count": len(assets),
            "multi_asset_peers": {
                peer: aids for peer, aids in sorted(multi.items())[:16]
            },
        },
    }


def detect_rare_tls_fingerprint(
    window: dict[str, Any],
    known_ja3: set[str] | None = None,
    known_ja4: set[str] | None = None,
    known_sni: set[str] | None = None,
) -> dict[str, Any] | None:
    """Flag rare JA3/JA4/SNI values not previously observed for the asset."""
    known_ja3 = known_ja3 or set()
    known_ja4 = known_ja4 or set()
    known_sni = known_sni or set()
    novel_ja3: list[str] = []
    novel_ja4: list[str] = []
    novel_sni: list[str] = []
    for flow in window.get("flows") or []:
        tls = flow.get("tls") if isinstance(flow.get("tls"), dict) else {}
        ja3 = tls.get("ja3")
        ja4 = tls.get("ja4")
        sni = tls.get("sni")
        if ja3 and ja3 not in known_ja3:
            novel_ja3.append(str(ja3))
        if ja4 and ja4 not in known_ja4:
            novel_ja4.append(str(ja4))
        if sni and sni not in known_sni:
            novel_sni.append(str(sni))
    novel_ja3 = sorted(set(novel_ja3))
    novel_ja4 = sorted(set(novel_ja4))
    novel_sni = sorted(set(novel_sni))
    if not (novel_ja3 or novel_ja4 or novel_sni):
        return None
    count = len(novel_ja3) + len(novel_ja4) + len(novel_sni)
    score = min(0.99, 0.5 + 0.08 * count)
    return {
        "detector": "rare_tls_fingerprint",
        "severity": "high" if count >= 3 else "medium",
        "score": round(score, 4),
        "mitre_tactics": ["TA0011"],
        "mitre_techniques": ["T1573", "T1071"],
        "evidence": {
            "novel_ja3": novel_ja3[:16],
            "novel_ja4": novel_ja4[:16],
            "novel_sni": novel_sni[:16],
            "count": count,
        },
    }


def detect_dns_tunneling_heuristic(window: dict[str, Any]) -> dict[str, Any] | None:
    """High-entropy or very long DNS queries suggest tunneling / DGA."""
    suspects: list[dict[str, Any]] = []
    for flow in window.get("flows") or []:
        dns = flow.get("dns") if isinstance(flow.get("dns"), dict) else {}
        if not dns:
            continue
        query = str(dns.get("query") or "")
        qlen = int(dns.get("query_length") or len(query) or 0)
        entropy = float(dns.get("entropy") or 0.0)
        # Long labels / high entropy on the full qname.
        if qlen >= 60 or entropy >= 4.0 or (qlen >= 40 and entropy >= 3.5):
            suspects.append(
                {
                    "query": query[:128],
                    "query_length": qlen,
                    "entropy": round(entropy, 4),
                    "peer_hash": flow.get("peer_hash"),
                }
            )
    if not suspects:
        return None
    # Prefer highest entropy.
    top = max(suspects, key=lambda s: (s["entropy"], s["query_length"]))
    score = min(
        0.99,
        0.55 + min(top["entropy"], 5.0) / 10.0 + min(top["query_length"], 120) / 400.0,
    )
    return {
        "detector": "dns_tunneling_heuristic",
        "severity": "high" if score >= 0.75 else "medium",
        "score": round(score, 4),
        "mitre_tactics": ["TA0011"],
        "mitre_techniques": ["T1071", "T1048"],
        "evidence": {
            "suspect_count": len(suspects),
            "top": top,
            "samples": suspects[:8],
        },
    }


def run_detectors(
    window: dict[str, Any],
    known_external_peers: set[str] | None = None,
    known_ja3: set[str] | None = None,
    known_ja4: set[str] | None = None,
    known_sni: set[str] | None = None,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for fn in (
        lambda w: detect_new_external_peer(w, known_external_peers),
        detect_port_scan_heuristic,
        detect_failed_connection_burst,
        detect_beaconing_heuristic,
        detect_cross_host_external_ip,
        lambda w: detect_rare_tls_fingerprint(w, known_ja3, known_ja4, known_sni),
        detect_dns_tunneling_heuristic,
    ):
        hit = fn(window)
        if hit is not None:
            findings.append(hit)
    return findings
