from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

_DENY_ACTIONS = frozenset(
    {"deny", "drop", "reject", "blocked", "block", "denied", "discard"}
)
_RULE_ADD = frozenset({"rule_add", "rule_create", "policy_add", "acl_add"})
_RULE_DELETE = frozenset(
    {"rule_delete", "rule_remove", "policy_delete", "acl_delete", "rule_del"}
)
_RULE_CHANGE = frozenset({"rule_change", "rule_modify", "policy_change", "acl_change"})


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
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError as exc:
            raise ValueError(f"invalid timestamp: {value!r}") from exc
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
    return event


def _classify_event_type(raw: str, action: str) -> str:
    key = raw.strip().lower().replace("-", "_").replace(" ", "_")
    if key in _RULE_ADD or key.endswith("_add"):
        return "rule_add"
    if key in _RULE_DELETE or key.endswith("_delete") or key.endswith("_remove"):
        return "rule_delete"
    if key in _RULE_CHANGE or "modify" in key:
        return "rule_change"
    if key in {"traffic", "session", "flow", "firewall_traffic", ""}:
        return "traffic"
    # Infer rule ops from action text when event_type omitted.
    act = action.lower()
    if "rule" in act and any(w in act for w in ("add", "create")):
        return "rule_add"
    if "rule" in act and any(w in act for w in ("delete", "remove")):
        return "rule_delete"
    return key or "traffic"


def normalize_firewall_event(event: dict[str, Any]) -> dict[str, Any]:
    """Canonical firewall event for features + detectors."""
    body = _payload(event)
    tenant_id = (
        event.get("tenant_id")
        or body.get("tenant_id")
        or (event.get("tenant") if isinstance(event.get("tenant"), str) else None)
        or "default"
    )
    asset = event.get("asset") if isinstance(event.get("asset"), dict) else {}
    asset_id = (
        event.get("asset_id")
        or body.get("asset_id")
        or asset.get("asset_id")
        or "unknown"
    )
    occurred_raw = (
        event.get("occurred_at")
        or body.get("occurred_at")
        or body.get("timestamp")
        or body.get("time")
        or event.get("timestamp")
    )
    occurred_at = _parse_ts(occurred_raw)

    action = str(
        body.get("action") or body.get("disposition") or body.get("outcome") or ""
    ).strip()
    event_type = _classify_event_type(
        str(body.get("event_type") or event.get("event_type") or ""),
        action,
    )
    action_l = action.lower()
    is_deny = action_l in _DENY_ACTIONS or event_type == "deny"

    src_ip = body.get("src_ip") or body.get("source_ip") or body.get("src")
    dst_ip = body.get("dst_ip") or body.get("destination_ip") or body.get("dst")
    rule_id = body.get("rule_id") or body.get("policy_id") or body.get("acl_id")
    rule_name = body.get("rule_name") or body.get("policy_name") or body.get("acl_name")

    return {
        "event_type": event_type,
        "tenant_id": str(tenant_id),
        "asset_id": str(asset_id),
        "service_id": body.get("service_id") or event.get("service_id"),
        "occurred_at": occurred_at.isoformat().replace("+00:00", "Z"),
        "action": action_l or ("deny" if is_deny else "allow"),
        "is_deny": bool(is_deny),
        "src_ip": str(src_ip) if src_ip else None,
        "dst_ip": str(dst_ip) if dst_ip else None,
        "src_port": body.get("src_port") or body.get("source_port"),
        "dst_port": body.get("dst_port") or body.get("destination_port"),
        "protocol": body.get("protocol") or body.get("proto"),
        "rule_id": str(rule_id) if rule_id is not None else None,
        "rule_name": str(rule_name) if rule_name is not None else None,
        "vendor": body.get("vendor") or body.get("device_vendor"),
        "raw_message": body.get("message") or body.get("raw"),
    }
