"""Shodan enrichment provider."""

from __future__ import annotations

import logging

import httpx

from black_onyx.enrichment.base import EnrichmentProvider, EnrichmentResult

logger = logging.getLogger(__name__)


class ShodanProvider(EnrichmentProvider):
    """Shodan API enrichment provider.

    Provides port scans, services, vulnerabilities, and host metadata for IPs.
    """

    def __init__(self, api_key: str) -> None:
        self._api_key = api_key
        self._base_url = "https://api.shodan.io"

    @property
    def name(self) -> str:
        return "shodan"

    @property
    def supported_ioc_types(self) -> list[str]:
        return ["ip"]

    async def enrich(self, ioc_type: str, ioc_value: str) -> EnrichmentResult:
        if not self._api_key:
            return EnrichmentResult(
                provider=self.name, ioc_type=ioc_type, ioc_value=ioc_value,
                error="No API key configured",
            )
        if ioc_type != "ip":
            return EnrichmentResult(
                provider=self.name, ioc_type=ioc_type, ioc_value=ioc_value,
                error=f"Unsupported IOC type: {ioc_type}",
            )

        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(
                    f"{self._base_url}/shodan/host/{ioc_value}",
                    params={"key": self._api_key},
                )
                if resp.status_code == 404:
                    return EnrichmentResult(
                        provider=self.name, ioc_type=ioc_type, ioc_value=ioc_value,
                        malicious=False, raw_data={}, tags=["no_shodan_data"],
                    )
                resp.raise_for_status()
                data = resp.json()
                tags = []
                if data.get("ports"):
                    tags.extend([f"port:{p}" for p in data["ports"][:10]])
                if data.get("vulns"):
                    tags.extend(data["vulns"][:10])
                if data.get("org"):
                    tags.append(f"org:{data['org']}")
                if data.get("os"):
                    tags.append(f"os:{data['os']}")
                if data.get("country_name"):
                    tags.append(f"country:{data['country_name']}")

                is_malicious = bool(data.get("vulns"))

                return EnrichmentResult(
                    provider=self.name, ioc_type=ioc_type, ioc_value=ioc_value,
                    malicious=is_malicious,
                    confidence=0.7 if is_malicious else 0.3,
                    tags=tags,
                    raw_data=data,
                )
        except Exception as e:
            logger.error(f"Shodan enrichment error for {ioc_value}: {e}")
            return EnrichmentResult(
                provider=self.name, ioc_type=ioc_type, ioc_value=ioc_value,
                error=str(e),
            )
