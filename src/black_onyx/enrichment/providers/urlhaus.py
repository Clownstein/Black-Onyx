"""URLhaus enrichment provider (abuse.ch)."""

from __future__ import annotations

import logging

import httpx

from black_onyx.enrichment.base import EnrichmentProvider, EnrichmentResult

logger = logging.getLogger(__name__)


class URLHausProvider(EnrichmentProvider):
    """URLhaus API enrichment provider (abuse.ch).

    Supports URL and domain lookups. No API key required.
    """

    def __init__(self) -> None:
        self._base_url = "https://urlhaus-api.abuse.ch/v1"

    @property
    def name(self) -> str:
        return "urlhaus"

    @property
    def supported_ioc_types(self) -> list[str]:
        return ["url", "domain"]

    async def enrich(self, ioc_type: str, ioc_value: str) -> EnrichmentResult:
        if ioc_type not in ("url", "domain"):
            return EnrichmentResult(
                provider=self.name, ioc_type=ioc_type, ioc_value=ioc_value,
                error=f"Unsupported IOC type: {ioc_type}",
            )

        try:
            async with httpx.AsyncClient(timeout=30) as client:
                if ioc_type == "url":
                    resp = await client.post(
                        f"{self._base_url}/",
                        data={"url": ioc_value},
                    )
                else:
                    resp = await client.post(
                        f"{self._base_url}/",
                        data={"host": ioc_value},
                    )
                resp.raise_for_status()
                data = resp.json()
                query_status = data.get("query_status", "")
                if query_status == "no_results":
                    return EnrichmentResult(
                        provider=self.name, ioc_type=ioc_type, ioc_value=ioc_value,
                        malicious=False, raw_data=data, tags=["not_found"],
                    )
                threat = data.get("threat", "")
                is_malicious = query_status == "ok" and bool(threat)
                tags = data.get("tags", []) if isinstance(data.get("tags"), list) else []
                if threat:
                    tags.append(threat)

                return EnrichmentResult(
                    provider=self.name, ioc_type=ioc_type, ioc_value=ioc_value,
                    malicious=is_malicious,
                    confidence=0.8 if is_malicious else 0.1,
                    tags=tags,
                    raw_data=data,
                )
        except Exception as e:
            logger.error(f"URLhaus enrichment error for {ioc_value}: {e}")
            return EnrichmentResult(
                provider=self.name, ioc_type=ioc_type, ioc_value=ioc_value,
                error=str(e),
            )
