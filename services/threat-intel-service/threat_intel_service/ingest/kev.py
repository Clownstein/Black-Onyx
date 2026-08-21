"""CISA Known Exploited Vulnerabilities (KEV) JSON ingest."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import httpx
from sqlalchemy.orm import Session
from ulid import ULID

from threat_intel_service.config import settings
from threat_intel_service.store import record_feed_health, upsert_indicator

SOURCE = "cisa-kev"
CONFIDENCE = 95


def _parse_date(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        # KEV uses YYYY-MM-DD
        if len(value) == 10:
            return datetime.strptime(value, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def vulnerability_to_indicator(vuln: dict[str, Any]) -> dict[str, Any] | None:
    cve = str(vuln.get("cveID") or vuln.get("cve_id") or "").strip()
    if not cve:
        return None
    labels = ["kev", "known_exploited"]
    if vuln.get("ransomwareUse"):
        labels.append(f"ransomware:{vuln['ransomwareUse']}")
    return {
        "indicator_id": f"ind-cisa-kev-{cve}",
        "tenant_id": None,
        "observable_type": "cve",
        "observable_value": cve,
        "source": SOURCE,
        "confidence": CONFIDENCE,
        "tlp": "clear",
        "valid_from": _parse_date(vuln.get("dateAdded")),
        "valid_until": None,
        "labels": labels,
        "campaigns": [],
        "mitre_techniques": [],
        "raw_json": vuln,
    }


async def sync_kev(
    session: Session,
    *,
    url: str | None = None,
    client: httpx.AsyncClient | None = None,
) -> dict[str, Any]:
    feed_url = url or settings.kev_url
    own_client = client is None
    client = client or httpx.AsyncClient(timeout=60.0)
    try:
        resp = await client.get(feed_url)
        resp.raise_for_status()
        payload = resp.json()
    except Exception as exc:
        record_feed_health(session, SOURCE, status="error", error=str(exc), indicator_count=0)
        session.commit()
        raise
    finally:
        if own_client:
            await client.aclose()

    vulns = payload.get("vulnerabilities") if isinstance(payload, dict) else None
    if not isinstance(vulns, list):
        vulns = payload if isinstance(payload, list) else []

    upserted = 0
    for vuln in vulns:
        if not isinstance(vuln, dict):
            continue
        data = vulnerability_to_indicator(vuln)
        if data is None:
            continue
        if not data.get("indicator_id"):
            data["indicator_id"] = f"ind-{ULID()}"
        upsert_indicator(session, data)
        upserted += 1

    record_feed_health(session, SOURCE, status="ok", error=None, indicator_count=upserted)
    session.commit()
    return {"source": SOURCE, "upserted": upserted, "status": "ok"}
