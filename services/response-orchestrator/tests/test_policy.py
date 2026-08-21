from response_orchestrator.policy import classify_response_mode, may_auto_execute


def test_vector_only_never_auto_executes() -> None:
    assert may_auto_execute({"vector_similarity": True, "calibrated_score": 0.99}) is False
    assert (
        may_auto_execute(
            {"vector_similarity": True, "calibrated_score": 0.99},
            {"soar.auto_vector_multi_signal": True},
        )
        is False
    )
    assert classify_response_mode({"vector_similarity": True}) == "suggest_only"


def test_multi_signal_with_policy_allows_auto() -> None:
    signals = {
        "exact_ti": True,
        "vector_similarity": True,
        "calibrated_score": 0.95,
    }
    policy = {"soar.auto_vector_multi_signal": True}
    assert may_auto_execute(signals, policy) is True
    assert classify_response_mode(signals, policy) == "gated_auto"
