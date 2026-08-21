"""Enrichment provider factory — creates provider instances from configuration."""

from __future__ import annotations

from black_onyx.enrichment.base import EnrichmentProvider


def create_enrichment_provider(
    provider_type: str,
    api_keys: dict[str, str] | None = None,
) -> EnrichmentProvider:
    """Create an enrichment provider instance from configuration.

    Args:
        provider_type: Provider name: "virustotal", "abuseipdb", "shodan",
                       "otx", "urlhaus", "threatfox", "nvd", "epss", "kev".
        api_keys: Dict mapping env var names to API key values.

    Returns:
        EnrichmentProvider instance.

    Raises:
        ValueError: If the provider type is unknown.
    """
    keys = api_keys or {}

    if provider_type == "virustotal":
        from black_onyx.enrichment.providers.virustotal import VirusTotalProvider
        return VirusTotalProvider(api_key=keys.get("VIRUSTOTAL_API_KEY", ""))

    elif provider_type == "abuseipdb":
        from black_onyx.enrichment.providers.abuseipdb import AbuseIPDBProvider
        return AbuseIPDBProvider(api_key=keys.get("ABUSEIPDB_API_KEY", ""))

    elif provider_type == "shodan":
        from black_onyx.enrichment.providers.shodan import ShodanProvider
        return ShodanProvider(api_key=keys.get("SHODAN_API_KEY", ""))

    elif provider_type == "otx":
        from black_onyx.enrichment.providers.otx import OTXProvider
        return OTXProvider(api_key=keys.get("OTX_API_KEY", ""))

    elif provider_type == "urlhaus":
        from black_onyx.enrichment.providers.urlhaus import URLHausProvider
        return URLHausProvider()

    elif provider_type == "threatfox":
        from black_onyx.enrichment.providers.threatfox import ThreatFoxProvider
        return ThreatFoxProvider()

    elif provider_type == "nvd":
        from black_onyx.enrichment.providers.nvd import NVDProvider
        return NVDProvider(api_key=keys.get("NVD_API_KEY", ""))

    elif provider_type == "epss":
        from black_onyx.enrichment.providers.epss import EPSSProvider
        return EPSSProvider()

    elif provider_type == "kev":
        from black_onyx.enrichment.providers.kev import KEVProvider
        return KEVProvider()

    else:
        raise ValueError(
            f"Unknown enrichment provider type: '{provider_type}'. "
            f"Supported: virustotal, abuseipdb, shodan, otx, urlhaus, threatfox, "
            f"nvd, epss, kev"
        )
