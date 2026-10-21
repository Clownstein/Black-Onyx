"""VirusTotal enrichment provider."""

from __future__ import annotations

import asyncio
import base64
import logging

import httpx

from black_onyx.enrichment.base import EnrichmentProvider, EnrichmentResult

logger = logging.getLogger(__name__)


class VirusTotalProvider(EnrichmentProvider):
    """VirusTotal v3 API enrichment provider.

    Supports IP, domain, hash, and URL lookups.
    Rate-limited to 4 requests/minute for free tier.
    """

    def __init__(self, api_key: str) -> None:
        self._api_key = api_key
        self._base_url = "https://www.virustotal.com/api/v3"
        self._semaphore = asyncio.Semaphore(4)

    @property
    def name(self) -> str:
        return "virustotal"

    @property
    def supported_ioc_types(self) -> list[str]:
        return ["ip", "domain", "hash", "url"]

    async def enrich(self, ioc_type: str, ioc_value: str) -> EnrichmentResult:
        if not self._api_key:
            return EnrichmentResult(
                provider=self.name, ioc_type=ioc_type, ioc_value=ioc_value,
                error="No API key configured",
            )

        endpoint_map = {
            "ip": "ip_addresses",
            "domain": "domains",
            "hash": "files",
            "url": "urls",
        }
        endpoint = endpoint_map.get(ioc_type)
        if not endpoint:
            return EnrichmentResult(
                provider=self.name, ioc_type=ioc_type, ioc_value=ioc_value,
                error=f"Unsupported IOC type: {ioc_type}",
            )

        lookup_value = ioc_value
        if ioc_type == "url":
            lookup_value = base64.urlsafe_b64encode(ioc_value.encode()).decode().strip("=")

        async with self._semaphore:
            try:
                async with httpx.AsyncClient(timeout=30) as client:
                    resp = await client.get(
                        f"{self._base_url}/{endpoint}/{lookup_value}",
                        headers={"x-apikey": self._api_key},
                    )
                    if resp.status_code == 404:
                        return EnrichmentResult(
                            provider=self.name, ioc_type=ioc_type, ioc_value=ioc_value,
                            malicious=False, raw_data={}, tags=["not_found"],
                        )
                    resp.raise_for_status()
                    data = resp.json()
                    attrs = data.get("data", {}).get("attributes", {})
                    stats = attrs.get("last_analysis_stats", {})
                    malicious_count = stats.get("malicious", 0)
                    is_malicious = malicious_count > 0
                    tags = []
                    if attrs.get("reputation", 0) < 0:
                        tags.append("bad_reputation")
                    if attrs.get("categories"):
                        tags.extend(list(attrs["categories"].values())[:5])

                    return EnrichmentResult(
                        provider=self.name, ioc_type=ioc_type, ioc_value=ioc_value,
                        malicious=is_malicious,
                        confidence=min(malicious_count / 70.0, 1.0) if malicious_count else 0.0,
                        tags=tags,
                        raw_data=data,
                    )
            except Exception as e:
                logger.error(f"VirusTotal enrichment error for {ioc_value}: {e}")
                return EnrichmentResult(
                    provider=self.name, ioc_type=ioc_type, ioc_value=ioc_value,
                    error=str(e),
                )
