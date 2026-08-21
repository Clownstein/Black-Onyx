"""AlienVault OTX enrichment provider."""

from __future__ import annotations

import logging

import httpx

from black_onyx.enrichment.base import EnrichmentProvider, EnrichmentResult

logger = logging.getLogger(__name__)


class OTXProvider(EnrichmentProvider):
    """AlienVault OTX API enrichment provider.

    Supports IP, domain, hash, email, URL, and CVE lookups.
    API key is optional; free tier works without it.
    """

    def __init__(self, api_key: str = "") -> None:
        self._api_key = api_key
        self._base_url = "https://otx.alienvault.com/api/v1/indicators"

    @property
    def name(self) -> str:
        return "otx"

    @property
    def supported_ioc_types(self) -> list[str]:
        return ["ip", "domain", "hash", "email", "url", "cve"]

    async def enrich(self, ioc_type: str, ioc_value: str) -> EnrichmentResult:
        type_map = {
            "ip": "ip",
            "domain": "domain",
            "hash": "file",
            "email": "email",
            "url": "url",
            "cve": "cve",
        }
        otx_type = type_map.get(ioc_type)
        if not otx_type:
            return EnrichmentResult(
                provider=self.name, ioc_type=ioc_type, ioc_value=ioc_value,
                error=f"Unsupported IOC type: {ioc_type}",
            )

        headers = {}
        if self._api_key:
            headers["X-OTX-API-KEY"] = self._api_key

        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(
                    f"{self._base_url}/{otx_type}/{ioc_value}/general",
                    headers=headers,
                )
                if resp.status_code == 404:
                    return EnrichmentResult(
                        provider=self.name, ioc_type=ioc_type, ioc_value=ioc_value,
                        malicious=False, raw_data={}, tags=["not_found"],
                    )
                resp.raise_for_status()
                data = resp.json()
                pulse_count = data.get("pulse_info", {}).get("count", 0)
                is_malicious = pulse_count > 0
                tags = []
                for pulse in data.get("pulse_info", {}).get("pulses", [])[:5]:
                    if pulse.get("name"):
                        tags.append(pulse["name"])
                    for t in pulse.get("tags", [])[:3]:
                        if t not in tags:
                            tags.append(t)

                return EnrichmentResult(
                    provider=self.name, ioc_type=ioc_type, ioc_value=ioc_value,
                    malicious=is_malicious,
                    confidence=min(pulse_count / 10.0, 1.0) if pulse_count else 0.0,
                    tags=tags,
                    raw_data=data,
                )
        except Exception as e:
            logger.error(f"OTX enrichment error for {ioc_value}: {e}")
            return EnrichmentResult(
                provider=self.name, ioc_type=ioc_type, ioc_value=ioc_value,
                error=str(e),
            )
