"""Composite threat scoring — aggregates enrichment results into a weighted score."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from black_onyx.enrichment.base import EnrichmentResult


# Default weights per provider (max points each can contribute)
DEFAULT_WEIGHTS: dict[str, float] = {
    "virustotal": 60.0,
    "abuseipdb": 35.0,
    "shodan": 25.0,
    "otx": 20.0,
    "urlhaus": 15.0,
    "threatfox": 15.0,
}

# Verdict thresholds
DEFAULT_THRESHOLDS = {
    "critical": 75,
    "high": 50,
    "medium": 25,
    "low": 0,
}


@dataclass
class ThreatScore:
    """Composite threat score for a single IOC."""

    ioc_value: str = ""
    ioc_type: str = ""
    score: float = 0.0
    verdict: str = "low"
    contributing_providers: list[dict[str, Any]] = field(default_factory=list)
    malicious_count: int = 0
    total_providers: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "ioc_value": self.ioc_value,
            "ioc_type": self.ioc_type,
            "score": round(self.score, 1),
            "verdict": self.verdict,
            "contributing_providers": self.contributing_providers,
            "malicious_count": self.malicious_count,
            "total_providers": self.total_providers,
        }


class ThreatScorer:
    """Aggregate enrichment results from multiple providers into a composite score.

    Each provider's confidence (0-100) is scaled by its weight and summed.
    The final score is clamped to 0-100 and mapped to a verdict.
    """

    def __init__(
        self,
        weights: dict[str, float] | None = None,
        thresholds: dict[str, int] | None = None,
    ) -> None:
        self._weights = weights or DEFAULT_WEIGHTS
        self._thresholds = thresholds or DEFAULT_THRESHOLDS

    def score_ioc(
        self,
        ioc_value: str,
        ioc_type: str,
        results: list[EnrichmentResult],
    ) -> ThreatScore:
        """Compute a composite threat score from enrichment results.

        Args:
            ioc_value: The IOC value.
            ioc_type: The IOC type (ip, domain, hash, url, email).
            results: List of EnrichmentResult from multiple providers.

        Returns:
            ThreatScore with aggregated score and verdict.
        """
        contributions: list[dict[str, Any]] = []
        total_weighted = 0.0
        total_max = 0.0
        malicious_count = 0

        for r in results:
            if r.error:
                continue
            weight = self._weights.get(r.provider, 10.0)
            confidence = r.confidence or 0.0
            # Scale confidence by provider weight
            scaled = (confidence / 100.0) * weight
            total_weighted += scaled
            total_max += weight
            if r.malicious:
                malicious_count += 1
            contributions.append({
                "provider": r.provider,
                "confidence": confidence,
                "weight": weight,
                "scaled_score": round(scaled, 1),
                "malicious": r.malicious,
                "tags": r.tags,
            })

        # Normalize to 0-100
        if total_max > 0:
            score = min(100.0, (total_weighted / total_max) * 100.0)
        else:
            score = 0.0

        # Bonus: if multiple providers flag as malicious, bump score
        if malicious_count >= 3:
            score = min(100.0, score + 10)
        elif malicious_count >= 2:
            score = min(100.0, score + 5)

        verdict = self._verdict(score)

        return ThreatScore(
            ioc_value=ioc_value,
            ioc_type=ioc_type,
            score=score,
            verdict=verdict,
            contributing_providers=contributions,
            malicious_count=malicious_count,
            total_providers=len([r for r in results if not r.error]),
        )

    def score_batch(
        self,
        ioc_results: dict[str, list[EnrichmentResult]],
    ) -> list[ThreatScore]:
        """Score a batch of IOCs.

        Args:
            ioc_results: Dict mapping ioc_value to list of EnrichmentResults.

        Returns:
            List of ThreatScore objects.
        """
        scores = []
        for ioc_value, results in ioc_results.items():
            ioc_type = results[0].ioc_type if results else "unknown"
            scores.append(self.score_ioc(ioc_value, ioc_type, results))
        return scores

    def _verdict(self, score: float) -> str:
        """Map a score to a verdict label."""
        if score >= self._thresholds["critical"]:
            return "critical"
        if score >= self._thresholds["high"]:
            return "high"
        if score >= self._thresholds["medium"]:
            return "medium"
        return "low"
