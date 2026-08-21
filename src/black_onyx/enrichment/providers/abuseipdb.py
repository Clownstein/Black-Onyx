"""AbuseIPDB enrichment provider."""

from __future__ import annotations

import logging

import httpx

from black_onyx.enrichment.base import EnrichmentProvider, EnrichmentResult

logger = logging.getLogger(__name__)


class AbuseIPDBProvider(EnrichmentProvider):
    """AbuseIPDB v2 API enrichment provider.

    Supports IP address lookups with abuse confidence scoring.
    """

    def __init__(self, api_key: str) -> None:
        self._api_key = api_key
        self._base_url = "https://api.abuseipdb.com/api/v2"

    @property
    def name(self) -> str:
        return "abuseipdb"

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
                    f"{self._base_url}/check",
                    params={"ipAddress": ioc_value, "maxAgeInDays": 90},
                    headers={"Key": self._api_key, "Accept": "application/json"},
                )
                resp.raise_for_status()
                data = resp.json().get("data", {})
                abuse_score = data.get("abuseConfidenceScore", 0)
                is_malicious = abuse_score >= 50
                tags = []
                if data.get("usageType"):
                    tags.append(data["usageType"])
                if data.get("isp"):
                    tags.append(data["isp"])
                if data.get("countryCode"):
                    tags.append(f"country:{data['countryCode']}")

                return EnrichmentResult(
                    provider=self.name, ioc_type=ioc_type, ioc_value=ioc_value,
                    malicious=is_malicious,
                    confidence=abuse_score / 100.0,
                    tags=tags,
                    raw_data=data,
                )
        except Exception as e:
            logger.error(f"AbuseIPDB enrichment error for {ioc_value}: {e}")
            return EnrichmentResult(
                provider=self.name, ioc_type=ioc_type, ioc_value=ioc_value,
                error=str(e),
            )
