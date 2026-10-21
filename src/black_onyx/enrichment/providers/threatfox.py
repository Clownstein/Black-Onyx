"""ThreatFox enrichment provider (abuse.ch)."""

from __future__ import annotations

import logging

import httpx

from black_onyx.enrichment.base import EnrichmentProvider, EnrichmentResult

logger = logging.getLogger(__name__)


class ThreatFoxProvider(EnrichmentProvider):
    """ThreatFox API enrichment provider (abuse.ch).

    Supports IP, domain, URL, and hash lookups. No API key required.
    """

    def __init__(self) -> None:
        self._base_url = "https://threatfox-api.abuse.ch/api/v1"

    @property
    def name(self) -> str:
        return "threatfox"

    @property
    def supported_ioc_types(self) -> list[str]:
        return ["ip", "domain", "url", "hash"]

    async def enrich(self, ioc_type: str, ioc_value: str) -> EnrichmentResult:
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.post(
                    f"{self._base_url}/",
                    json={"query": "search_ioc", "search_term": ioc_value},
                )
                resp.raise_for_status()
                data = resp.json()
                query_status = data.get("query_status", "")
                if query_status != "ok":
                    return EnrichmentResult(
                        provider=self.name, ioc_type=ioc_type, ioc_value=ioc_value,
                        malicious=False, raw_data=data, tags=[query_status],
                    )

                results = data.get("data", [])
                if not results:
                    return EnrichmentResult(
                        provider=self.name, ioc_type=ioc_type, ioc_value=ioc_value,
                        malicious=False, raw_data=data, tags=["no_results"],
                    )

                first = results[0]
                is_malicious = True
                tags = []
                if first.get("malware"):
                    tags.append(f"malware:{first['malware']}")
                if first.get("threat_type"):
                    tags.append(first["threat_type"])
                if first.get("confidence_level"):
                    conf = int(first.get("confidence_level", 0))
                    confidence = conf / 100.0
                else:
                    confidence = 0.7

                return EnrichmentResult(
                    provider=self.name, ioc_type=ioc_type, ioc_value=ioc_value,
                    malicious=is_malicious,
                    confidence=confidence,
                    tags=tags,
                    raw_data=data,
                )
        except Exception as e:
            logger.error(f"ThreatFox enrichment error for {ioc_value}: {e}")
            return EnrichmentResult(
                provider=self.name, ioc_type=ioc_type, ioc_value=ioc_value,
                error=str(e),
            )
