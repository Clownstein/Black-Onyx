"""Vector-aware SOAR auto-execute policy (human-gated by default)."""

from __future__ import annotations

from typing import Any


def may_auto_execute(
    signals: dict[str, Any] | None,
    tenant_policy: dict[str, Any] | None = None,
    *,
    calibrated_score_threshold: float = 0.9,
) -> bool:
    """Return True only for explicit multi-signal + tenant policy.

    Vector-only (or vector+novelty alone) must never auto-execute.
    """
    signals = signals or {}
    policy = tenant_policy or {}
    if not bool(policy.get("soar.auto_vector_multi_signal")):
        return False

    exact_ti = bool(signals.get("exact_ti") or signals.get("ti_exact"))
    vector_sim = bool(signals.get("vector_similarity") or signals.get("vector_neighbor"))
    novelty = bool(signals.get("vector_novelty"))
    score = float(signals.get("calibrated_score") or 0.0)

    independent = sum(
        1
        for flag in (exact_ti, vector_sim or novelty, score >= calibrated_score_threshold)
        if flag
    )
    # Require exact TI + (vector signal) + high calibrated score
    return bool(exact_ti and (vector_sim or novelty) and score >= calibrated_score_threshold and independent >= 3)


def classify_response_mode(
    signals: dict[str, Any] | None,
    tenant_policy: dict[str, Any] | None = None,
) -> str:
    """suggest_only | gated_auto."""
    return "gated_auto" if may_auto_execute(signals, tenant_policy) else "suggest_only"
