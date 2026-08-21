"""Enrichment framework — IOC enrichment via external threat intelligence APIs."""

from black_onyx.enrichment.base import EnrichmentProvider, EnrichmentResult
from black_onyx.enrichment.factory import create_enrichment_provider
from black_onyx.enrichment.scorer import ThreatScorer, ThreatScore

__all__ = [
    "EnrichmentProvider",
    "EnrichmentResult",
    "create_enrichment_provider",
    "ThreatScorer",
    "ThreatScore",
]
