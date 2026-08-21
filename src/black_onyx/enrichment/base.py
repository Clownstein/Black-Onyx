"""Abstract base class for IOC enrichment providers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class EnrichmentResult:
    """Container for enrichment data."""

    provider: str = ""
    ioc_type: str = ""
    ioc_value: str = ""
    malicious: bool | None = None
    confidence: float | None = None
    tags: list[str] = field(default_factory=list)
    raw_data: dict[str, Any] = field(default_factory=dict)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "ioc_type": self.ioc_type,
            "ioc_value": self.ioc_value,
            "malicious": self.malicious,
            "confidence": self.confidence,
            "tags": self.tags,
            "raw_data": self.raw_data,
            "error": self.error,
        }


class EnrichmentProvider(ABC):
    """Abstract base class for IOC enrichment providers.

    All providers must implement the enrich() method.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Provider name (e.g. 'virustotal', 'abuseipdb', 'shodan')."""

    @property
    def supported_ioc_types(self) -> list[str]:
        """List of IOC types this provider can enrich (e.g. ['ip', 'domain', 'hash'])."""
        return []

    @abstractmethod
    async def enrich(self, ioc_type: str, ioc_value: str) -> EnrichmentResult:
        """Enrich a single IOC.

        Args:
            ioc_type: Type of IOC ('ip', 'domain', 'hash', 'url', 'email').
            ioc_value: The IOC value to enrich.

        Returns:
            EnrichmentResult with enrichment data.
        """

    def test_connection(self) -> dict[str, Any]:
        """Test the provider connection.

        Returns:
            Dict with "status" ("ok" or "error") and optional "error" message.
        """
        return {"status": "ok", "provider": self.name}
