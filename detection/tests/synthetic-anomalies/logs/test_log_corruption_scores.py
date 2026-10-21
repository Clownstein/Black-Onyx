from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
LOG_MODEL = ROOT / "models" / "log-model"
FIXTURES_DIR = Path(__file__).resolve().parent

for path in (LOG_MODEL, FIXTURES_DIR):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from fixtures import CORRUPTIONS, normal_sequence  # noqa: E402
from log_model.scorer import LogAnomalyScorer  # noqa: E402


@pytest.fixture(scope="module")
def scorer() -> LogAnomalyScorer:
    return LogAnomalyScorer(artifacts_dir=LOG_MODEL / "artifacts")


def _score(scorer: LogAnomalyScorer, events: list[dict]) -> float:
    out = scorer.predict(
        {
            "request_id": "synth-1",
            "tenant_id": "tenant-synth",
            "model_name": "log-transformer",
            "feature_version": "1.0",
            "items": [{"sequence_id": "s1", "events": events}],
        }
    )
    return float(out["results"][0]["calibrated_score"])


def test_corrupt_sequences_score_higher_than_normal(scorer: LogAnomalyScorer) -> None:
    baseline = _score(scorer, normal_sequence())
    for name, factory in CORRUPTIONS.items():
        corrupt_score = _score(scorer, factory())
        assert corrupt_score > baseline, f"{name}: {corrupt_score} <= {baseline}"
