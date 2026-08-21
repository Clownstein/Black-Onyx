"""HTTP client for threat-intel-service match API."""

from __future__ import annotations

from typing import Any

import httpx

from integration_hub.config import settings


async def match_cves(cves: list[str]) -> dict[str, dict[str, Any]]:
    """Return map CVE → match payload for hits (KEV / TI store).

    Calls ``POST {threat_intel_url}/api/v1/match`` with observable type ``cve``.
    Failures return an empty map (ingest still succeeds without boost).
    """
    unique = sorted({c.upper() for c in cves if c and str(c).upper().startswith("CVE-")})
    if not unique:
        return {}
    url = settings.threat_intel_url.rstrip("/") + "/api/v1/match"
    body = {"observables": [{"type": "cve", "value": cve} for cve in unique]}
    headers: dict[str, str] = {}
    key = (settings.threat_intel_service_key or "").strip()
    if key:
        headers["X-Service-Key"] = key
    try:
        async with httpx.AsyncClient(timeout=settings.threat_intel_timeout_seconds) as client:
            response = await client.post(url, json=body, headers=headers)
            response.raise_for_status()
            data = response.json()
    except Exception:
        return {}

    hits: dict[str, dict[str, Any]] = {}
    matches = data.get("matches") or []
    if not isinstance(matches, list):
        return hits
    for match in matches:
        if not isinstance(match, dict):
            continue
        value = str(match.get("value") or "").upper()
        mtype = str(match.get("type") or "").lower()
        if mtype in {"cve", "vulnerability"} and value.startswith("CVE-"):
            hits[value] = match
        # Some stores may return source=kev without type=cve
        source = str(match.get("source") or "").lower()
        if value.startswith("CVE-") and ("kev" in source or mtype == "cve"):
            hits[value] = match
    return hits
