from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

# Suricata severity: 1 = highest, 4 = lowest.
_SEVERITY_MAP: dict[int, tuple[str, float]] = {
    1: ("critical", 0.95),
    2: ("high", 0.80),
    3: ("medium", 0.55),
    4: ("low", 0.30),
}


def suricata_severity_to_score(severity: int | None) -> tuple[str, float]:
    """Map Suricata alert severity (1–4) to severity_hint + calibrated_score."""
    if severity is None:
        return "medium", 0.55
    try:
        key = int(severity)
    except (TypeError, ValueError):
        return "medium", 0.55
    return _SEVERITY_MAP.get(key, ("medium", 0.55))


def _parse_ts(value: Any) -> datetime:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
    if isinstance(value, (int, float)):
        ts = float(value)
        if ts > 1e12:
            ts /= 1000.0
        return datetime.fromtimestamp(ts, tz=timezone.utc)
    if isinstance(value, str) and value.strip():
        text = value.strip().replace("Z", "+00:00")
        # Suricata often uses "+0000" without colon.
        if len(text) >= 5 and text[-5] in "+-" and text[-3] != ":":
            text = text[:-2] + ":" + text[-2:]
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            return datetime.now(tz=timezone.utc)
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    return datetime.now(tz=timezone.utc)


def _payload(event: dict[str, Any]) -> dict[str, Any]:
    if isinstance(event.get("payload"), dict):
        return event["payload"]
    if isinstance(event.get("extensions"), dict):
        raw = event["extensions"].get("raw_payload")
        if isinstance(raw, dict):
            return raw
        # Suricata fields may live directly under extensions.
        if "alert" in event["extensions"]:
            return event["extensions"]
    return event


def normalize_suricata_alert(event: dict[str, Any]) -> dict[str, Any]:
    """Canonical Suricata alert for finding emission."""
    body = _payload(event)
    alert = body.get("alert") if isinstance(body.get("alert"), dict) else {}
    if not alert and isinstance(event.get("alert"), dict):
        alert = event["alert"]
        body = {**body, **{k: v for k, v in event.items() if k != "alert"}}

    tenant_id = str(event.get("tenant_id") or body.get("tenant_id") or "default")
    asset = event.get("asset") if isinstance(event.get("asset"), dict) else {}
    asset_id = str(
        event.get("asset_id")
        or body.get("asset_id")
        or asset.get("asset_id")
        or "unknown"
    )
    occurred = _parse_ts(
        event.get("occurred_at")
        or body.get("timestamp")
        or body.get("occurred_at")
        or event.get("timestamp")
    )

    signature_id = alert.get("signature_id") or alert.get("sid")
    try:
        signature_id = int(signature_id) if signature_id is not None else 0
    except (TypeError, ValueError):
        signature_id = 0

    signature = str(alert.get("signature") or alert.get("msg") or "suricata.alert")
    severity_raw = alert.get("severity")
    try:
        severity = int(severity_raw) if severity_raw is not None else 3
    except (TypeError, ValueError):
        severity = 3

    severity_hint, score = suricata_severity_to_score(severity)

    mitre_tactics = list(
        body.get("mitre_tactics") or event.get("mitre_tactics") or []
    )
    mitre_techniques = list(
        body.get("mitre_techniques") or event.get("mitre_techniques") or []
    )
    # Pull MITRE from alert.metadata when present (Suricata ET style).
    meta = alert.get("metadata") if isinstance(alert.get("metadata"), dict) else {}
    for key, dest in (
        ("mitre_tactic_id", mitre_tactics),
        ("mitre_technique_id", mitre_techniques),
    ):
        val = meta.get(key)
        if isinstance(val, list):
            for item in val:
                if item and str(item) not in dest:
                    dest.append(str(item))
        elif val and str(val) not in dest:
            dest.append(str(val))

    return {
        "event_type": "suricata.alert",
        "tenant_id": tenant_id,
        "asset_id": asset_id,
        "service_id": body.get("service_id") or event.get("service_id"),
        "occurred_at": occurred.isoformat().replace("+00:00", "Z"),
        "signature_id": signature_id,
        "signature": signature,
        "category": alert.get("category"),
        "action": alert.get("action"),
        "gid": alert.get("gid"),
        "rev": alert.get("rev"),
        "suricata_severity": severity,
        "severity_hint": severity_hint,
        "calibrated_score": score,
        "community_id": body.get("community_id") or event.get("community_id"),
        "flow_id": body.get("flow_id") or event.get("flow_id"),
        "src_ip_hash": body.get("src_ip_hash") or body.get("src_ip"),
        "dest_ip_hash": body.get("dest_ip_hash")
        or body.get("dest_ip")
        or body.get("dst_ip_hash")
        or body.get("dst_ip"),
        "src_port": body.get("src_port"),
        "dest_port": body.get("dest_port") or body.get("dst_port"),
        "proto": body.get("proto") or body.get("protocol"),
        "sensor_id": body.get("sensor_id") or event.get("sensor_id"),
        "mitre_tactics": mitre_tactics,
        "mitre_techniques": mitre_techniques,
        "pcap_bytes": body.get("pcap_bytes") or event.get("pcap_bytes"),
        "pcap_path": body.get("pcap_path") or event.get("pcap_path"),
        "pcap_b64": body.get("pcap_b64") or event.get("pcap_b64"),
    }
