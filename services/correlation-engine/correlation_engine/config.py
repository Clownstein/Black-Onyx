from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="CORRELATION_", extra="ignore")

    kafka_brokers: str = "localhost:19092"
    finding_topics: str = (
        "findings.logs,findings.code,findings.network,findings.metrics,"
        "findings.host-state,findings.firewall,findings.malware"
    )
    group_id: str = "correlation-engine"
    topic_dlq: str = "findings.correlation.dlq"
    incident_api_url: str = "http://localhost:8083"
    notification_url: str = "http://notification-service:8086/api/v1/notifications/incident"
    host: str = "0.0.0.0"
    port: int = 8084
    initial_window_minutes: int = 15
    window_minutes: int = 15
    asset_criticality_default: float = 0.5
    severity_medium: float = 0.60
    severity_high: float = 0.80
    severity_critical: float = 0.93
    # logistic coefficients used by the simplified path (b0 + b1*max_log + b5*criticality)
    b0: float = -1.5
    b1: float = 3.0
    b5: float = 1.0
    redis_url: str = ""
    incident_api_service_key: str = ""
    notification_api_key: str = ""
    threat_intel_url: str = ""
    threat_intel_service_key: str = ""
    vector_search_enabled: bool = Field(
        default=False,
        validation_alias=AliasChoices("VECTOR_SEARCH_ENABLED", "CORRELATION_VECTOR_SEARCH_ENABLED"),
    )
    qdrant_url: str = Field(
        default="",
        validation_alias=AliasChoices("QDRANT_URL", "CORRELATION_QDRANT_URL"),
    )
    embedding_service_url: str = Field(
        default="",
        validation_alias=AliasChoices(
            "EMBEDDING_SERVICE_URL",
            "CORRELATION_EMBEDDING_SERVICE_URL",
        ),
    )
    vector_novelty_enabled: bool = Field(
        default=False,
        validation_alias=AliasChoices(
            "VECTOR_NOVELTY_ENABLED",
            "CORRELATION_VECTOR_NOVELTY_ENABLED",
        ),
    )


settings = Settings()
