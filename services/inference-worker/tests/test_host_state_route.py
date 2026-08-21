from __future__ import annotations

from inference_worker.config import Settings, TopicRoute


def test_host_state_route_scores_without_publishing() -> None:
    settings = Settings()
    assert "host-state.features" in settings.consume_topics()
    assert settings.model_name_for("host-state.features") == "host-state-model"
    assert settings.findings_topic_for("host-state.features") == "findings.host-state"
    assert settings.publish_findings_for("host-state.features") is False
    assert settings.publish_findings_for("logs.features") is True
    assert settings.direct_model_url("host-state-model").endswith(":8104")


def test_topic_route_defaults_publish_true() -> None:
    route = TopicRoute(
        feature_topic="logs.features",
        model_name="log-model",
        findings_topic="findings.logs",
    )
    assert route.publish_findings is True
