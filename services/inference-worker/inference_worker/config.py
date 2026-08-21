from __future__ import annotations

from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class TopicRoute(BaseModel):
    """Map a Kafka feature topic to a model and findings topic."""

    feature_topic: str
    model_name: str
    findings_topic: str
    # When false, score for observability but do not publish/persist findings
    # (used for host-state: processor already emits golden rule findings).
    publish_findings: bool = True


DEFAULT_TOPIC_ROUTES: list[dict[str, object]] = [
    {
        "feature_topic": "logs.features",
        "model_name": "log-model",
        "findings_topic": "findings.logs",
    },
    {
        "feature_topic": "network.features",
        "model_name": "network-model",
        "findings_topic": "findings.network",
    },
    {
        "feature_topic": "metrics.features",
        "model_name": "metrics-model",
        "findings_topic": "findings.metrics",
    },
    {
        "feature_topic": "code.features",
        "model_name": "code-model",
        "findings_topic": "findings.code",
    },
    {
        "feature_topic": "host-state.features",
        "model_name": "host-state-model",
        "findings_topic": "findings.host-state",
        "publish_findings": False,
    },
]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="INFER_", extra="ignore")

    kafka_brokers: str = "localhost:19092"
    model_gateway_url: str = "http://localhost:8091"
    incident_api_url: str = "http://localhost:8083"
    persist_findings: bool = True
    group_id: str = "inference-worker"
    host: str = "0.0.0.0"
    port: int = 8088

    # When false, call model URLs directly instead of the gateway.
    use_model_gateway: bool = True

    log_model_url: str = "http://localhost:8090"
    network_model_url: str = "http://localhost:8101"
    metrics_model_url: str = "http://localhost:8102"
    code_model_url: str = "http://localhost:8103"
    host_state_model_url: str = "http://localhost:8104"

    # Extra topic that carries pre-built code advisory findings to normalize.
    code_findings_topic: str = "code.findings"
    code_findings_out_topic: str = "findings.code"

    topic_routes: list[dict[str, object]] = Field(default_factory=lambda: list(DEFAULT_TOPIC_ROUTES))

    request_timeout_seconds: float = 10.0
    dlq_suffix: str = ".dlq"
    api_key: str = ""
    incident_api_service_key: str = ""

    def routes(self) -> list[TopicRoute]:
        return [TopicRoute(**route) for route in self.topic_routes]

    def consume_topics(self) -> list[str]:
        topics = [r.feature_topic for r in self.routes()]
        if self.code_findings_topic and self.code_findings_topic not in topics:
            topics.append(self.code_findings_topic)
        return topics

    def findings_topic_for(self, feature_topic: str) -> str | None:
        for route in self.routes():
            if route.feature_topic == feature_topic:
                return route.findings_topic
        if feature_topic == self.code_findings_topic:
            return self.code_findings_out_topic
        return None

    def publish_findings_for(self, feature_topic: str) -> bool:
        for route in self.routes():
            if route.feature_topic == feature_topic:
                return route.publish_findings
        if feature_topic == self.code_findings_topic:
            return True
        return True

    def model_name_for(self, feature_topic: str) -> str | None:
        for route in self.routes():
            if route.feature_topic == feature_topic:
                return route.model_name
        return None

    def direct_model_url(self, model_name: str) -> str:
        mapping = {
            "log-model": self.log_model_url,
            "network-model": self.network_model_url,
            "metrics-model": self.metrics_model_url,
            "code-model": self.code_model_url,
            "host-state-model": self.host_state_model_url,
            "host-state": self.host_state_model_url,
        }
        try:
            return mapping[model_name]
        except KeyError as exc:
            raise ValueError(f"unknown model_name: {model_name}") from exc


settings = Settings()
