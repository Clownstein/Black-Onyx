"""Best-effort STIX 2.1 indicator pattern parsing and bundle upsert."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session
from ulid import ULID

from threat_intel_service.store import upsert_indicator

# STIX cyber observable type → platform observable_type
_STIX_TYPE_MAP = {
    "ipv4-addr": "ipv4",
    "ipv6-addr": "ipv6",
    "domain-name": "domain",
    "url": "url",
    "email-addr": "email",
    "file": "file_hash",
}

_PATTERN_RE = re.compile(
    r"\[(?P<otype>[a-z0-9\-]+):(?P<field>[^\s=\]]+)\s*=\s*['\"](?P<value>[^'\"]+)['\"]\s*\]",
    re.IGNORECASE,
)

_HASH_FIELD_RE = re.compile(
    r"hashes\.(?:['\"]?(?:SHA-256|SHA256|SHA-1|SHA1|MD5|ssdeep)['\"]?)",
    re.IGNORECASE,
)


def _parse_dt(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def extract_observables_from_pattern(pattern: str) -> list[tuple[str, str]]:
    """Return list of (observable_type, value) from a STIX pattern string."""
    results: list[tuple[str, str]] = []
    if not pattern:
        return results
    for match in _PATTERN_RE.finditer(pattern):
        stix_type = match.group("otype").lower()
        field = match.group("field")
        value = match.group("value").strip()
        if not value:
            continue
        if stix_type == "file" or _HASH_FIELD_RE.search(field):
            results.append(("file_hash", value.lower()))
            continue
        mapped = _STIX_TYPE_MAP.get(stix_type)
        if mapped:
            results.append((mapped, value))
    return results


def stix_indicator_to_rows(obj: dict[str, Any], *, default_source: str = "stix-upload") -> list[dict[str, Any]]:
    """Convert one STIX indicator object into one or more store rows."""
    pattern = str(obj.get("pattern") or "")
    observables = extract_observables_from_pattern(pattern)
    if not observables:
        return []

    source = default_source
    external_refs = obj.get("external_references") or []
    if isinstance(external_refs, list):
        for ref in external_refs:
            if isinstance(ref, dict) and ref.get("source_name"):
                source = str(ref["source_name"])
                break

    confidence = obj.get("confidence")
    if confidence is None:
        confidence = 70
    try:
        confidence = max(0, min(100, int(confidence)))
    except (TypeError, ValueError):
        confidence = 70

    labels = list(obj.get("labels") or [])
    tlp = None
    for label in labels:
        low = str(label).lower()
        if low.startswith("tlp:"):
            tlp = low.split(":", 1)[1]
        elif low in {"white", "green", "amber", "red", "clear"}:
            tlp = low

    stix_id = str(obj.get("id") or f"indicator--{ULID()}")
    rows: list[dict[str, Any]] = []
    for otype, value in observables:
        rows.append(
            {
                "indicator_id": f"ind-{stix_id}-{otype}-{ULID()}"[:120],
                "tenant_id": None,
                "observable_type": otype,
                "observable_value": value,
                "source": source,
                "confidence": confidence,
                "tlp": tlp,
                "valid_from": _parse_dt(obj.get("valid_from")),
                "valid_until": _parse_dt(obj.get("valid_until")),
                "labels": labels,
                "campaigns": [],
                "mitre_techniques": [],
                "raw_json": obj,
            }
        )
    return rows


def ingest_stix_bundle(
    session: Session,
    bundle: dict[str, Any],
    *,
    default_source: str = "stix-upload",
) -> dict[str, Any]:
    objects = bundle.get("objects") if isinstance(bundle, dict) else None
    if not isinstance(objects, list):
        objects = []

    upserted = 0
    skipped = 0
    for obj in objects:
        if not isinstance(obj, dict):
            skipped += 1
            continue
        if obj.get("type") != "indicator":
            continue
        rows = stix_indicator_to_rows(obj, default_source=default_source)
        if not rows:
            skipped += 1
            continue
        for row in rows:
            upsert_indicator(session, row)
            upserted += 1

    session.commit()
    return {"upserted": upserted, "skipped": skipped, "status": "ok"}
