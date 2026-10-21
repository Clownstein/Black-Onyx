"""Shared helpers for the sensor/cloud flow adapters.

Zeek, DNS, AWS, GCP, and Azure adapters all need the same three primitives:
pull the inner payload out of an ingest envelope, map an IANA protocol number
to a name, and render an epoch timestamp as a canonical `...Z` ISO string.
Keeping one copy avoids the drift a per-adapter copy invites.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

# IANA protocol numbers used by cloud flow-log formats (AWS/GCP emit numbers).
PROTOCOL_BY_NUMBER: dict[int, str] = {1: "icmp", 6: "tcp", 17: "udp"}


def extract_payload(event: dict[str, Any]) -> dict[str, Any]:
    """Return the inner payload dict from an ingest envelope.

    Prefers `payload`, then `extensions.raw_payload`, else the event itself.
    """
    if isinstance(event.get("payload"), dict):
        return event["payload"]
    if isinstance(event.get("extensions"), dict):
        raw = event["extensions"].get("raw_payload")
        if isinstance(raw, dict):
            return raw
    return event


def iso_from_epoch(ts: float) -> str:
    """Render an epoch timestamp (seconds or ms) as a canonical `...Z` string."""
    ts = float(ts)
    if ts > 1e12:  # milliseconds
        ts /= 1000.0
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat().replace("+00:00", "Z")
