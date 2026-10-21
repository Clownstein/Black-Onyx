from __future__ import annotations

from pydantic import AliasChoices, Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """profile-evaluator settings.

    Accepts the documented env names (``INCIDENT_API_URL``,
    ``PROFILE_EVALUATOR_INTERVAL_SEC``, ``VECTOR_NOVELTY_ENABLED``,
    ``PROFILE_PROBE_URLS``) as well as prefixed fallbacks.
    """

    model_config = SettingsConfigDict(extra="ignore")

    host: str = Field(default="0.0.0.0", validation_alias=AliasChoices("PROFILE_EVALUATOR_HOST"))
    port: int = Field(default=8116, validation_alias=AliasChoices("PROFILE_EVALUATOR_PORT"))
    api_key: str = Field(default="", validation_alias=AliasChoices("PROFILE_EVALUATOR_API_KEY"))

    incident_api_url: str = Field(
        default="http://localhost:8083",
        validation_alias=AliasChoices(
            "INCIDENT_API_URL", "PROFILE_EVALUATOR_INCIDENT_API_URL"
        ),
    )
    incident_api_service_key: str = Field(
        default="",
        validation_alias=AliasChoices(
            "PROFILE_EVALUATOR_INCIDENT_API_SERVICE_KEY", "INCIDENT_API_SERVICE_KEY"
        ),
    )
    tenant_id: str = Field(
        default="",
        validation_alias=AliasChoices("PROFILE_EVALUATOR_TENANT_ID"),
    )
    role: str = Field(
        default="analyst",
        validation_alias=AliasChoices("PROFILE_EVALUATOR_ROLE"),
    )

    interval_sec: float = Field(
        default=300.0,
        ge=5.0,
        le=86_400.0,
        validation_alias=AliasChoices("PROFILE_EVALUATOR_INTERVAL_SEC"),
    )
    # The periodic loop is disabled by default; evaluation can be triggered via
    # the HTTP endpoint. Enable explicitly to run the cron loop.
    enable_loop: bool = Field(
        default=False,
        validation_alias=AliasChoices("PROFILE_EVALUATOR_ENABLE_LOOP"),
    )

    vector_novelty_enabled: bool = Field(
        default=False,
        validation_alias=AliasChoices(
            "VECTOR_NOVELTY_ENABLED", "PROFILE_EVALUATOR_VECTOR_NOVELTY_ENABLED"
        ),
    )
    qdrant_url: str | None = Field(
        default=None,
        validation_alias=AliasChoices("QDRANT_URL", "PROFILE_EVALUATOR_QDRANT_URL"),
    )
    embedding_service_url: str | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "EMBEDDING_SERVICE_URL",
            "PROFILE_EVALUATOR_EMBEDDING_SERVICE_URL",
        ),
    )
    embedding_service_api_key: str = ""

    probe_urls: str = Field(
        default="",
        validation_alias=AliasChoices("PROFILE_PROBE_URLS", "PROFILE_EVALUATOR_PROBE_URLS"),
    )
    probe_timeout_sec: float = Field(
        default=5.0,
        gt=0.0,
        le=60.0,
        validation_alias=AliasChoices("PROFILE_EVALUATOR_PROBE_TIMEOUT_SEC"),
    )

    http_timeout_sec: float = Field(
        default=10.0,
        gt=0.0,
        le=120.0,
        validation_alias=AliasChoices("PROFILE_EVALUATOR_HTTP_TIMEOUT_SEC"),
    )

    def probe_url_list(self) -> list[str]:
        return [u.strip() for u in self.probe_urls.split(",") if u.strip()]

    @model_validator(mode="after")
    def validate_enabled_capabilities(self) -> "Settings":
        if self.enable_loop and not self.tenant_id.strip():
            raise ValueError("PROFILE_EVALUATOR_TENANT_ID is required when the loop is enabled")
        if self.enable_loop and not self.incident_api_service_key.strip():
            raise ValueError("incident-api service key is required when the loop is enabled")
        if self.vector_novelty_enabled and not self.tenant_id.strip():
            raise ValueError("PROFILE_EVALUATOR_TENANT_ID is required for vector novelty")
        return self


settings = Settings()
