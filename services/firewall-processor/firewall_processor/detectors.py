from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from firewall_processor.config import settings


def _parse_iso(value: str | None) -> datetime:
    if not value:
        return datetime.now(tz=timezone.utc)
    text = value.replace("Z", "+00:00")
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def detect_deny_spike(
    events: list[dict[str, Any]],
    *,
    threshold: int | None = None,
) -> list[dict[str, Any]]:
    """Many deny actions from one source IP within the batch/window."""
    limit = threshold if threshold is not None else settings.deny_spike_threshold
    by_src: dict[str, list[dict[str, Any]]] = {}
    for event in events:
        if not event.get("is_deny"):
            continue
        src = event.get("src_ip")
        if not src:
            continue
        by_src.setdefault(str(src), []).append(event)

    hits: list[dict[str, Any]] = []
    for src, rows in by_src.items():
        if len(rows) < limit:
            continue
        assets = sorted({str(r.get("asset_id") or "unknown") for r in rows})
        score = min(0.99, 0.55 + len(rows) / 100.0)
        hits.append(
            {
                "detector": "deny_spike",
                "severity": "high" if len(rows) >= limit * 2 else "medium",
                "score": round(score, 4),
                "mitre_tactics": ["TA0001", "TA0043"],
                "mitre_techniques": ["T1190", "T1595"],
                "evidence": {
                    "src_ip": src,
                    "deny_count": len(rows),
                    "threshold": limit,
                    "asset_ids": assets,
                    "sample_dst": [
                        r.get("dst_ip") for r in rows[:8] if r.get("dst_ip")
                    ],
                },
                "asset_id": assets[0] if len(assets) == 1 else assets[0],
                "tenant_id": rows[0].get("tenant_id") or "default",
                "occurred_at": rows[-1].get("occurred_at"),
            }
        )
    return hits


def detect_rule_change_outside_window(
    event: dict[str, Any],
    *,
    start_hour: int | None = None,
    end_hour: int | None = None,
) -> dict[str, Any] | None:
    """rule_add / rule_delete outside the approved UTC change window → high."""
    event_type = str(event.get("event_type") or "")
    if event_type not in {"rule_add", "rule_delete"}:
        return None
    start = (
        start_hour
        if start_hour is not None
        else settings.change_window_start_hour_utc
    )
    end = end_hour if end_hour is not None else settings.change_window_end_hour_utc
    occurred = _parse_iso(str(event.get("occurred_at") or ""))
    hour = occurred.hour
    inside = start <= hour < end if start < end else hour >= start or hour < end
    if inside:
        return None
    return {
        "detector": "rule_change_outside_window",
        "severity": "high",
        "score": 0.9,
        "mitre_tactics": ["TA0003", "TA0005"],
        "mitre_techniques": ["T1562", "T1078"],
        "evidence": {
            "event_type": event_type,
            "occurred_at": event.get("occurred_at"),
            "hour_utc": hour,
            "approved_window_utc": f"{start:02d}:00-{end:02d}:00",
            "rule_id": event.get("rule_id"),
            "rule_name": event.get("rule_name"),
            "action": event.get("action"),
        },
        "asset_id": event.get("asset_id") or "unknown",
        "tenant_id": event.get("tenant_id") or "default",
        "occurred_at": event.get("occurred_at"),
    }


def run_detectors(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    detections: list[dict[str, Any]] = []
    detections.extend(detect_deny_spike(events))
    for event in events:
        hit = detect_rule_change_outside_window(event)
        if hit is not None:
            detections.append(hit)
    return detections
