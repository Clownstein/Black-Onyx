"""FIRST EPSS enrichment provider."""

from __future__ import annotations

import logging
from typing import Any

import httpx

from black_onyx.enrichment.base import EnrichmentProvider, EnrichmentResult

logger = logging.getLogger(__name__)


class EPSSProvider(EnrichmentProvider):
    """FIRST EPSS API enrichment provider.

    Returns exploit prediction scores for CVE IDs. No API key required.
    """

    def __init__(self) -> None:
        self._base_url = "https://api.first.org/data/v1/epss"

    @property
    def name(self) -> str:
        return "epss"

    @property
    def supported_ioc_types(self) -> list[str]:
        return ["cve"]

    async def enrich(self, ioc_type: str, ioc_value: str) -> EnrichmentResult:
        if ioc_type != "cve":
            return EnrichmentResult(
                provider=self.name, ioc_type=ioc_type, ioc_value=ioc_value,
                error=f"Unsupported IOC type: {ioc_type}",
            )

        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(
                    self._base_url,
                    params={"cve": ioc_value.upper()},
                )
                resp.raise_for_status()
                data = resp.json()
                entries = data.get("data") or []
                if not entries:
                    return EnrichmentResult(
                        provider=self.name, ioc_type=ioc_type, ioc_value=ioc_value,
                        malicious=False, raw_data=data, tags=["not_found"],
                        confidence=0.0,
                    )

                entry = entries[0]
                epss_raw = entry.get("epss", 0)
                percentile_raw = entry.get("percentile", 0)
                try:
                    epss_score = float(epss_raw)
                except (TypeError, ValueError):
                    epss_score = 0.0
                try:
                    percentile = float(percentile_raw)
                except (TypeError, ValueError):
                    percentile = 0.0

                raw_data: dict[str, Any] = {
                    "cve": entry.get("cve", ioc_value.upper()),
                    "epss": epss_score,
                    "percentile": percentile,
                    "date": entry.get("date"),
                }
                tags = [f"epss:{epss_score}", f"percentile:{percentile}"]

                return EnrichmentResult(
                    provider=self.name, ioc_type=ioc_type, ioc_value=ioc_value,
                    malicious=None,
                    confidence=epss_score,
                    tags=tags,
                    raw_data=raw_data,
                )
        except Exception as e:
            logger.error(f"EPSS enrichment error for {ioc_value}: {e}")
            return EnrichmentResult(
                provider=self.name, ioc_type=ioc_type, ioc_value=ioc_value,
                error=str(e),
            )
