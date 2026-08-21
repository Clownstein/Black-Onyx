"""Push TIP-published indicators into Postgres threat_intel (match-on-wire SoR)."""

from __future__ import annotations

import logging
import os
from typing import Any

import httpx

logger = logging.getLogger(__name__)

_TYPE_MAP = {
    "ip": "ipv4",
    "ipv4": "ipv4",
    "ipv6": "ipv6",
    "domain": "domain",
    "hostname": "domain",
    "url": "url",
    "hash": "hash",
    "md5": "hash",
    "sha1": "hash",
    "sha256": "hash",
    "email": "email",
    "cve": "cve",
}


def _normalize_type(ioc_type: str) -> str:
    key = (ioc_type or "").strip().lower()
    return _TYPE_MAP.get(key, key or "indicator")


async def sync_indicators_to_threat_intel(
    iocs: list[dict[str, Any]],
    *,
    source: str = "black-onyx-tip",
    tenant_id: str = "default",
) -> dict[str, Any]:
    """Best-effort upsert of TIP IOCs into detection threat-intel-service."""
    base = os.environ.get("BLACK_ONYX_THREAT_INTEL_URL", "http://threat-intel-service:8098").rstrip("/")
    key = (
        os.environ.get("THREAT_INTEL_SERVICE_KEY")
        or os.environ.get("THREAT_INTEL_SERVICE_API_KEY")
        or ""
    ).strip()
    indicators = []
    for row in iocs:
        value = str(row.get("ioc_value") or row.get("value") or "").strip()
        if not value:
            continue
        indicators.append(
            {
                "observable_type": _normalize_type(str(row.get("ioc_type") or row.get("type") or "")),
                "observable_value": value,
                "source": source,
                "confidence": int(row.get("confidence") or 70),
                "tlp": row.get("tlp") or "amber",
                "tenant_id": tenant_id,
                "labels": list(row.get("labels") or ["tip-publish"]),
            }
        )
    if not indicators:
        return {"status": "skipped", "upserted": 0, "reason": "no indicators"}
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if key:
        headers["X-Service-Key"] = key
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                f"{base}/api/v1/indicators/upsert",
                json={"indicators": indicators},
                headers=headers,
            )
            if resp.status_code >= 400:
                return {
                    "status": "error",
                    "upserted": 0,
                    "reason": f"HTTP {resp.status_code}: {resp.text[:300]}",
                }
            body = resp.json() if resp.content else {}
            return {
                "status": "ok",
                "upserted": int(body.get("upserted") or len(indicators)),
                "upstream": body,
            }
    except httpx.HTTPError as exc:
        logger.warning("threat-intel sync unavailable: %s", exc)
        return {"status": "unavailable", "upserted": 0, "reason": exc.__class__.__name__}
