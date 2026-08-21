"""Cross-modality kill-chain heuristics for correlated findings."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from correlation_engine.scoring import FindingView

# Boost applied when code + metrics + network findings co-occur in the window.
KILL_CHAIN_BOOST = 0.12
HOST_NETWORK_KILL_CHAIN_BOOST = 0.1
SURICATA_FLOW_BOOST = 0.15
MALWARE_C2_NETWORK_BOOST = 0.18
DEFAULT_WINDOW_MINUTES = 30


def _modality(finding: FindingView) -> str | None:
    ft = (finding.finding_type or "").lower()
    model = (finding.model_name or "").lower()
    blob = f"{ft} {model}"
    if "malware" in blob:
        return "malware"
    if "code" in blob:
        return "code"
    if "metric" in blob:
        return "metrics"
    if "suricata" in blob or "ids" in blob:
        return "suricata"
    if "net" in blob or "flow" in blob or "firewall" in blob:
        return "network"
    if "log" in blob:
        return "log"
    if "host" in blob:
        return "host_state"
    return None


def _finding_time(f: FindingView) -> datetime:
    for candidate in (f.window_end, f.window_start):
        if candidate is not None:
            return candidate if candidate.tzinfo else candidate.replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc)


def _within_window(findings: list[FindingView], window_minutes: int) -> bool:
    times = [_finding_time(f) for f in findings]
    if not times:
        return False
    return (max(times) - min(times)) <= timedelta(minutes=window_minutes)


def _join_keys(finding: FindingView) -> set[str]:
    ctx = finding.context or {}
    keys: set[str] = set()
    for field in ("community_id", "zeek_uid", "flow_id", "asset_id"):
        val = ctx.get(field)
        if val:
            keys.add(f"{field}:{val}")
    if finding.asset_id:
        keys.add(f"asset_id:{finding.asset_id}")
    return keys


def detect_code_metrics_network_kill_chain(
    findings: list[FindingView],
    *,
    window_minutes: int = DEFAULT_WINDOW_MINUTES,
) -> dict[str, Any] | None:
    """Return kill-chain hit metadata when code+metrics+network appear within window."""
    by_mod: dict[str, list[FindingView]] = {"code": [], "metrics": [], "network": []}
    for f in findings:
        mod = _modality(f)
        if mod == "suricata":
            mod = "network"
        if mod in by_mod:
            by_mod[mod].append(f)

    if not all(by_mod[m] for m in ("code", "metrics", "network")):
        return None

    relevant = [f for f in findings if _modality(f) in {"code", "metrics", "network", "suricata"}]
    if not _within_window(relevant, window_minutes):
        return None

    times = [_finding_time(f) for f in relevant]
    span = max(times) - min(times)
    return {
        "kill_chain": "code_metrics_network",
        "window_minutes": window_minutes,
        "span_seconds": int(span.total_seconds()),
        "finding_ids": {
            "code": [f.finding_id for f in by_mod["code"]],
            "metrics": [f.finding_id for f in by_mod["metrics"]],
            "network": [f.finding_id for f in by_mod["network"]],
        },
        "boost": KILL_CHAIN_BOOST,
    }


def detect_host_network_kill_chain(
    findings: list[FindingView],
    *,
    window_minutes: int = DEFAULT_WINDOW_MINUTES,
) -> dict[str, Any] | None:
    """Host-state + network co-occurrence (process/beacon style cross-model chain)."""
    by_mod: dict[str, list[FindingView]] = {"host_state": [], "network": []}
    for f in findings:
        mod = _modality(f)
        if mod == "suricata":
            mod = "network"
        if mod in by_mod:
            by_mod[mod].append(f)

    if not by_mod["host_state"] or not by_mod["network"]:
        return None

    relevant = [f for f in findings if _modality(f) in {"host_state", "network", "suricata"}]
    if not _within_window(relevant, window_minutes):
        return None

    times = [_finding_time(f) for f in relevant]
    span = max(times) - min(times)
    return {
        "kill_chain": "host_network",
        "window_minutes": window_minutes,
        "span_seconds": int(span.total_seconds()),
        "finding_ids": {
            "host_state": [f.finding_id for f in by_mod["host_state"]],
            "network": [f.finding_id for f in by_mod["network"]],
        },
        "boost": HOST_NETWORK_KILL_CHAIN_BOOST,
    }


def detect_suricata_flow_coincidence(
    findings: list[FindingView],
    *,
    window_minutes: int = DEFAULT_WINDOW_MINUTES,
) -> dict[str, Any] | None:
    """Boost when Suricata SID finding coincides with flow anomaly (shared join keys)."""
    suricata: list[FindingView] = []
    flows: list[FindingView] = []
    for f in findings:
        mod = _modality(f)
        ft = (f.finding_type or "").lower()
        if mod == "suricata" or "suricata" in ft or any(
            c.get("type") == "suricata_alert" for c in f.contributors
        ):
            suricata.append(f)
        elif mod == "network" or "flow" in ft or any(
            c.get("type") in {"new_external_peer", "port_scan_heuristic", "failed_connection_burst", "beaconing"}
            for c in f.contributors
        ):
            flows.append(f)

    if not suricata or not flows:
        return None
    if not _within_window(suricata + flows, window_minutes):
        return None

    shared: set[str] = set()
    for s in suricata:
        skeys = _join_keys(s)
        for fl in flows:
            overlap = skeys & _join_keys(fl)
            shared |= overlap
    # Even without shared keys, same asset bucket already implies coincidence;
    # prefer stronger boost when community_id/zeek_uid/asset_id overlap.
    boost = SURICATA_FLOW_BOOST + (0.05 if shared else 0.0)
    return {
        "kill_chain": "suricata_flow",
        "window_minutes": window_minutes,
        "join_keys": sorted(shared),
        "finding_ids": {
            "suricata": [f.finding_id for f in suricata],
            "flow": [f.finding_id for f in flows],
        },
        "boost": boost,
        "signature_ids": [
            f.context.get("signature_id") for f in suricata if f.context.get("signature_id") is not None
        ],
    }


def detect_malware_c2_network(
    findings: list[FindingView],
    *,
    window_minutes: int = DEFAULT_WINDOW_MINUTES,
) -> dict[str, Any] | None:
    """Boost when malware finding network.hosts overlap network/TI context."""
    malware = [f for f in findings if _modality(f) == "malware" or "malware" in (f.finding_type or "").lower()]
    networkish = [
        f
        for f in findings
        if _modality(f) in {"network", "suricata"} or "network" in (f.finding_type or "").lower()
    ]
    if not malware:
        return None

    hosts: set[str] = set()
    for f in malware:
        net = f.context.get("network") if isinstance(f.context.get("network"), dict) else {}
        for h in list(net.get("hosts") or []) + list(f.context.get("hosts") or []):
            hosts.add(str(h).lower())
        for h in list(f.context.get("iocs") or []):
            hosts.add(str(h).lower())

    if not hosts:
        return None

    overlap: set[str] = set()
    for f in networkish:
        ctx = f.context or {}
        candidates = []
        for key in ("dst", "dest_ip", "peer", "host", "domain", "sni"):
            if ctx.get(key):
                candidates.append(str(ctx[key]).lower())
        for peer in ctx.get("peers") or []:
            if isinstance(peer, dict) and peer.get("peer"):
                candidates.append(str(peer["peer"]).lower())
            elif isinstance(peer, str):
                candidates.append(peer.lower())
        for c in candidates:
            if c in hosts:
                overlap.add(c)

    if not overlap and not networkish:
        # Malware alone with C2 hosts still warrants a modest boost when hosts present.
        if not _within_window(malware, window_minutes):
            return None
        return {
            "kill_chain": "malware_c2",
            "window_minutes": window_minutes,
            "hosts": sorted(hosts)[:20],
            "overlap": [],
            "finding_ids": {"malware": [f.finding_id for f in malware], "network": []},
            "boost": MALWARE_C2_NETWORK_BOOST * 0.5,
        }

    if not overlap:
        return None
    if not _within_window(malware + networkish, window_minutes):
        return None

    return {
        "kill_chain": "malware_c2_network",
        "window_minutes": window_minutes,
        "hosts": sorted(hosts)[:20],
        "overlap": sorted(overlap)[:20],
        "finding_ids": {
            "malware": [f.finding_id for f in malware],
            "network": [f.finding_id for f in networkish],
        },
        "boost": MALWARE_C2_NETWORK_BOOST,
    }


def apply_kill_chain_boost(incident: dict[str, Any], findings: list[FindingView]) -> None:
    """Boost risk_score and annotate context when kill-chain pattern(s) match."""
    hits = [
        h
        for h in (
            detect_code_metrics_network_kill_chain(findings),
            detect_host_network_kill_chain(findings),
            detect_suricata_flow_coincidence(findings),
            detect_malware_c2_network(findings),
        )
        if h
    ]
    if not hits:
        return

    total_boost = sum(float(h["boost"]) for h in hits)
    incident["risk_score"] = round(
        min(1.0, float(incident.get("risk_score") or 0.0) + total_boost),
        4,
    )
    context = dict(incident.get("context") or {})
    primary = hits[0]
    context["kill_chain"] = primary
    context["kill_chains"] = hits
    # Surface join keys for analysts
    join_keys: list[str] = []
    for h in hits:
        join_keys.extend(list(h.get("join_keys") or []))
    if join_keys:
        context["join_keys"] = sorted(set(join_keys))
    incident["context"] = context
    cats = list(incident.get("category") or [])
    if "kill_chain" not in cats:
        cats.append("kill_chain")
    for h in hits:
        name = str(h.get("kill_chain") or "")
        if name and name not in cats:
            cats.append(name)
    incident["category"] = cats
