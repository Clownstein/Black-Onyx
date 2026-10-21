"""NVD CVE API 2.0 enrichment provider."""

from __future__ import annotations

import logging
import os
from typing import Any

import httpx

from black_onyx.enrichment.base import EnrichmentProvider, EnrichmentResult

logger = logging.getLogger(__name__)


class NVDProvider(EnrichmentProvider):
    """NVD CVE API 2.0 enrichment provider.

    Looks up CVE records by ID. Optional API key via NVD_API_KEY for higher rate limits.
    """

    def __init__(self, api_key: str = "") -> None:
        self._api_key = api_key or os.environ.get("NVD_API_KEY", "")
        self._base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    @property
    def name(self) -> str:
        return "nvd"

    @property
    def supported_ioc_types(self) -> list[str]:
        return ["cve"]

    @staticmethod
    def _extract_cvss(cve: dict[str, Any]) -> tuple[float | None, str | None]:
        """Return (baseScore, baseSeverity) from preferred CVSS metric block."""
        metrics = cve.get("metrics") or {}
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key)
            if not isinstance(entries, list) or not entries:
                continue
            cvss_data = entries[0].get("cvssData") or {}
            score = cvss_data.get("baseScore")
            severity = cvss_data.get("baseSeverity") or entries[0].get("baseSeverity")
            if score is not None:
                return float(score), str(severity) if severity else None
        return None, None

    @staticmethod
    def _extract_tags(cve: dict[str, Any], cvss_score: float | None, severity: str | None) -> list[str]:
        tags: list[str] = []
        if severity:
            tags.append(f"severity:{severity.lower()}")
        if cvss_score is not None:
            tags.append(f"cvss:{cvss_score}")
        for weakness in cve.get("weaknesses") or []:
            for desc in weakness.get("description") or []:
                value = desc.get("value")
                if value and value not in tags:
                    tags.append(value)
        return tags

    async def enrich(self, ioc_type: str, ioc_value: str) -> EnrichmentResult:
        if ioc_type != "cve":
            return EnrichmentResult(
                provider=self.name, ioc_type=ioc_type, ioc_value=ioc_value,
                error=f"Unsupported IOC type: {ioc_type}",
            )

        headers: dict[str, str] = {"Accept": "application/json"}
        if self._api_key:
            headers["apiKey"] = self._api_key

        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(
                    self._base_url,
                    params={"cveId": ioc_value.upper()},
                    headers=headers,
                )
                if resp.status_code == 404:
                    return EnrichmentResult(
                        provider=self.name, ioc_type=ioc_type, ioc_value=ioc_value,
                        malicious=False, raw_data={}, tags=["not_found"],
                    )
                resp.raise_for_status()
                data = resp.json()
                vulnerabilities = data.get("vulnerabilities") or []
                if not vulnerabilities:
                    return EnrichmentResult(
                        provider=self.name, ioc_type=ioc_type, ioc_value=ioc_value,
                        malicious=False, raw_data=data, tags=["not_found"],
                    )

                cve = vulnerabilities[0].get("cve") or {}
                cvss_score, severity = self._extract_cvss(cve)
                tags = self._extract_tags(cve, cvss_score, severity)
                raw_data: dict[str, Any] = dict(cve)
                if cvss_score is not None:
                    raw_data["cvss"] = cvss_score
                if severity:
                    raw_data["cvss_severity"] = severity

                confidence = (cvss_score / 10.0) if cvss_score is not None else 0.0

                return EnrichmentResult(
                    provider=self.name, ioc_type=ioc_type, ioc_value=ioc_value,
                    malicious=None,
                    confidence=confidence,
                    tags=tags,
                    raw_data=raw_data,
                )
        except Exception as e:
            logger.error(f"NVD enrichment error for {ioc_value}: {e}")
            return EnrichmentResult(
                provider=self.name, ioc_type=ioc_type, ioc_value=ioc_value,
                error=str(e),
            )
