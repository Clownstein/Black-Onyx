"""Tests for composite threat scoring (scorer.py)."""

import pytest

from black_onyx.enrichment.base import EnrichmentResult
from black_onyx.enrichment.scorer import (
    DEFAULT_THRESHOLDS,
    DEFAULT_WEIGHTS,
    ThreatScore,
    ThreatScorer,
)


@pytest.fixture
def scorer() -> ThreatScorer:
    return ThreatScorer()


@pytest.fixture
def clean_results() -> list[EnrichmentResult]:
    """Enrichment results with no malicious flags."""
    return [
        EnrichmentResult(provider="virustotal", ioc_type="ip", ioc_value="1.2.3.4", malicious=False, confidence=10.0, tags=[]),
        EnrichmentResult(provider="abuseipdb", ioc_type="ip", ioc_value="1.2.3.4", malicious=False, confidence=5.0, tags=[]),
    ]


@pytest.fixture
def malicious_results() -> list[EnrichmentResult]:
    """Enrichment results with multiple malicious flags."""
    return [
        EnrichmentResult(provider="virustotal", ioc_type="ip", ioc_value="1.2.3.4", malicious=True, confidence=90.0, tags=["malware"]),
        EnrichmentResult(provider="abuseipdb", ioc_type="ip", ioc_value="1.2.3.4", malicious=True, confidence=85.0, tags=["abuse"]),
        EnrichmentResult(provider="shodan", ioc_type="ip", ioc_value="1.2.3.4", malicious=False, confidence=50.0, tags=[]),
    ]


@pytest.fixture
def error_results() -> list[EnrichmentResult]:
    """Enrichment results with errors."""
    return [
        EnrichmentResult(provider="virustotal", ioc_type="ip", ioc_value="1.2.3.4", malicious=False, confidence=0.0, tags=[], error="API key missing"),
        EnrichmentResult(provider="abuseipdb", ioc_type="ip", ioc_value="1.2.3.4", malicious=True, confidence=80.0, tags=[]),
    ]


class TestThreatScorer:
    def test_default_weights(self):
        assert "virustotal" in DEFAULT_WEIGHTS
        assert DEFAULT_WEIGHTS["virustotal"] == 60.0

    def test_default_thresholds(self):
        assert DEFAULT_THRESHOLDS["critical"] == 75
        assert DEFAULT_THRESHOLDS["low"] == 0

    def test_score_clean_ioc(self, scorer, clean_results):
        score = scorer.score_ioc("1.2.3.4", "ip", clean_results)
        assert score.ioc_value == "1.2.3.4"
        assert score.ioc_type == "ip"
        assert score.score < 25  # Should be low
        assert score.verdict == "low"
        assert score.malicious_count == 0
        assert score.total_providers == 2

    def test_score_malicious_ioc(self, scorer, malicious_results):
        score = scorer.score_ioc("1.2.3.4", "ip", malicious_results)
        assert score.score >= 50  # Should be high
        assert score.verdict in ("high", "critical")
        assert score.malicious_count == 2
        assert score.total_providers == 3
        assert len(score.contributing_providers) == 3

    def test_score_with_errors(self, scorer, error_results):
        score = scorer.score_ioc("1.2.3.4", "ip", error_results)
        # Only abuseipdb should contribute (virustotal has error)
        assert score.total_providers == 1
        assert len(score.contributing_providers) == 1
        assert score.contributing_providers[0]["provider"] == "abuseipdb"

    def test_score_empty_results(self, scorer):
        score = scorer.score_ioc("1.2.3.4", "ip", [])
        assert score.score == 0.0
        assert score.verdict == "low"
        assert score.total_providers == 0

    def test_score_clamped_to_100(self, scorer):
        results = [
            EnrichmentResult(provider=p, ioc_type="ip", ioc_value="x", malicious=True, confidence=100.0, tags=[])
            for p in DEFAULT_WEIGHTS
        ]
        score = scorer.score_ioc("x", "ip", results)
        assert score.score <= 100.0

    def test_malicious_bonus(self, scorer):
        results = [
            EnrichmentResult(provider=p, ioc_type="ip", ioc_value="x", malicious=True, confidence=100.0, tags=[])
            for p in ["virustotal", "abuseipdb", "shodan", "otx", "urlhaus", "threatfox"]
        ]
        score = scorer.score_ioc("x", "ip", results)
        # 6 malicious providers → bonus +10
        assert score.malicious_count == 6
        assert score.score == 100.0  # Clamped

    def test_custom_weights(self):
        scorer = ThreatScorer(weights={"custom_provider": 100.0})
        results = [
            EnrichmentResult(provider="custom_provider", ioc_type="ip", ioc_value="x", malicious=True, confidence=100.0, tags=[]),
        ]
        score = scorer.score_ioc("x", "ip", results)
        assert score.score == 100.0

    def test_custom_thresholds(self):
        scorer = ThreatScorer(thresholds={"critical": 90, "high": 70, "medium": 40, "low": 0})
        results = [
            EnrichmentResult(provider="virustotal", ioc_type="ip", ioc_value="x", malicious=True, confidence=80.0, tags=[]),
        ]
        score = scorer.score_ioc("x", "ip", results)
        # Normalized: (80/100 * 60) / 60 * 100 = 80 → high with custom thresholds
        assert score.verdict == "high"

    def test_score_batch(self, scorer, malicious_results, clean_results):
        ioc_results = {
            "1.2.3.4": malicious_results,
            "5.6.7.8": clean_results,
        }
        scores = scorer.score_batch(ioc_results)
        assert len(scores) == 2
        values = {s.ioc_value for s in scores}
        assert "1.2.3.4" in values
        assert "5.6.7.8" in values

    def test_threat_score_to_dict(self):
        ts = ThreatScore(
            ioc_value="1.2.3.4",
            ioc_type="ip",
            score=75.5,
            verdict="critical",
            contributing_providers=[{"provider": "test"}],
            malicious_count=2,
            total_providers=3,
        )
        d = ts.to_dict()
        assert d["ioc_value"] == "1.2.3.4"
        assert d["score"] == 75.5
        assert d["verdict"] == "critical"
        assert d["malicious_count"] == 2
