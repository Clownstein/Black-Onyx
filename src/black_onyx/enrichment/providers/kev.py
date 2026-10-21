"""CISA Known Exploited Vulnerabilities (KEV) enrichment provider."""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

import httpx

from black_onyx.enrichment.base import EnrichmentProvider, EnrichmentResult

logger = logging.getLogger(__name__)

KEV_FEED_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)
DEFAULT_CACHE_TTL_SECONDS = 6 * 3600


class KEVProvider(EnrichmentProvider):
    """CISA KEV catalog enrichment provider.

    Fetches the public KEV JSON feed, caches it in memory with a TTL,
    and looks up CVE IDs. Entries present in KEV are marked malicious.
    """

    def __init__(self, cache_ttl_seconds: int = DEFAULT_CACHE_TTL_SECONDS) -> None:
        self._cache_ttl = cache_ttl_seconds
        self._cache: dict[str, dict[str, Any]] | None = None
        self._cache_fetched_at: float = 0.0
        self._lock = asyncio.Lock()

    @property
    def name(self) -> str:
        return "kev"

    @property
    def supported_ioc_types(self) -> list[str]:
        return ["cve"]

    def _cache_valid(self) -> bool:
        return (
            self._cache is not None
            and (time.monotonic() - self._cache_fetched_at) < self._cache_ttl
        )

    async def _ensure_catalog(self) -> dict[str, dict[str, Any]]:
        if self._cache_valid() and self._cache is not None:
            return self._cache

        async with self._lock:
            if self._cache_valid() and self._cache is not None:
                return self._cache

            async with httpx.AsyncClient(timeout=60) as client:
                resp = await client.get(KEV_FEED_URL)
                resp.raise_for_status()
                payload = resp.json()

            index: dict[str, dict[str, Any]] = {}
            for vuln in payload.get("vulnerabilities") or []:
                cve_id = (vuln.get("cveID") or "").upper()
                if cve_id:
                    index[cve_id] = vuln

            self._cache = index
            self._cache_fetched_at = time.monotonic()
            logger.info("Loaded CISA KEV catalog with %d entries", len(index))
            return index

    async def enrich(self, ioc_type: str, ioc_value: str) -> EnrichmentResult:
        if ioc_type != "cve":
            return EnrichmentResult(
                provider=self.name, ioc_type=ioc_type, ioc_value=ioc_value,
                error=f"Unsupported IOC type: {ioc_type}",
            )

        try:
            catalog = await self._ensure_catalog()
            cve_key = ioc_value.upper()
            entry = catalog.get(cve_key)
            if entry is None:
                return EnrichmentResult(
                    provider=self.name, ioc_type=ioc_type, ioc_value=ioc_value,
                    malicious=False,
                    confidence=0.0,
                    tags=["not_in_kev"],
                    raw_data={"in_kev": False},
                )

            tags = ["in_kev"]
            if entry.get("vendorProject"):
                tags.append(f"vendor:{entry['vendorProject']}")
            if entry.get("product"):
                tags.append(f"product:{entry['product']}")
            if entry.get("knownRansomwareCampaignUse"):
                tags.append(f"ransomware:{entry['knownRansomwareCampaignUse']}")

            raw_data = dict(entry)
            raw_data["in_kev"] = True

            return EnrichmentResult(
                provider=self.name, ioc_type=ioc_type, ioc_value=ioc_value,
                malicious=True,
                confidence=1.0,
                tags=tags,
                raw_data=raw_data,
            )
        except Exception as e:
            logger.error(f"KEV enrichment error for {ioc_value}: {e}")
            return EnrichmentResult(
                provider=self.name, ioc_type=ioc_type, ioc_value=ioc_value,
                error=str(e),
            )
