from pathlib import Path

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


def _default_antares_cli_src() -> str:
    here = Path(__file__).resolve()
    candidate = (
        here.parents[3]
        / "models"
        / "antares-1b"
        / "assets"
        / "antares-cli"
        / "src"
    )
    return str(candidate)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="CODE_ENRICHMENT_",
        extra="ignore",
        populate_by_name=True,
    )

    host: str = "0.0.0.0"
    port: int = 8110
    kafka_brokers: str = "localhost:19092"
    topic_enrichment: str = "code.enrichment"
    topic_dlq: str = "code.enrichment.dlq"
    consumer_group: str = "code-enrichment-worker"
    enable_kafka: bool = True

    # OpenAI-compatible Antares completions endpoint. Empty → plan/CWE-only (degraded).
    antares_endpoint: str = Field(
        default="",
        validation_alias=AliasChoices(
            "CODE_ENRICHMENT_ANTARES_ENDPOINT",
            "ANTARES_ENDPOINT",
        ),
    )
    antares_api_key: str = Field(
        default="",
        validation_alias=AliasChoices(
            "CODE_ENRICHMENT_ANTARES_API_KEY",
            "ANTARES_API_KEY",
        ),
    )
    antares_cli_src: str = Field(default_factory=_default_antares_cli_src)
    antares_timeout_seconds: float = 600.0
    antares_tool_budget: int = 20

    incident_api_url: str = "http://localhost:8083"
    incident_api_service_key: str = Field(
        default="dev-service-key",
        validation_alias=AliasChoices(
            "CODE_ENRICHMENT_INCIDENT_API_SERVICE_KEY",
            "INCIDENT_API_SERVICE_KEY",
        ),
    )
    incident_api_timeout_seconds: float = 15.0

    poll_findings: bool = False
    poll_interval_seconds: float = 60.0
    poll_min_score: float = 0.7
    poll_tenant_id: str = "default"

    human_review_required: bool = True


settings = Settings()
