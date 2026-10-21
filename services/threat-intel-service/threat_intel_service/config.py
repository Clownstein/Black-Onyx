from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="THREAT_INTEL_", extra="ignore")

    database_url: str = "postgresql+psycopg://anomaly:anomaly@localhost:5432/threat_intel"
    host: str = "0.0.0.0"
    port: int = 8098
    service_api_key: str = ""
    airgap_mode: bool = False
    taxii_url: str | None = None
    taxii_token: str | None = None
    taxii_username: str | None = None
    taxii_password: str | None = None
    taxii_page_limit: int = Field(default=100, ge=1, le=1000)
    taxii_max_pages: int = Field(default=100, ge=1, le=1000)
    misp_url: str | None = None
    misp_key: str | None = None
    misp_page_size: int = Field(default=500, ge=1, le=5000)
    misp_max_pages: int = Field(default=100, ge=1, le=1000)
    max_response_bytes: int = Field(default=16 * 1024 * 1024, ge=1024, le=128 * 1024 * 1024)
    kev_url: str = (
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    )
    # Vector / semantic matching is optional and reports disabled/degraded
    # capability states when its real dependencies are unavailable.
    vector_search_enabled: bool = Field(
        default=False,
        validation_alias=AliasChoices(
            "VECTOR_SEARCH_ENABLED", "THREAT_INTEL_VECTOR_SEARCH_ENABLED"
        ),
    )
    qdrant_url: str | None = Field(
        default=None,
        validation_alias=AliasChoices("QDRANT_URL", "THREAT_INTEL_QDRANT_URL"),
    )
    embedding_service_url: str | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "EMBEDDING_SERVICE_URL",
            "THREAT_INTEL_EMBEDDING_SERVICE_URL",
        ),
    )
    embedding_service_api_key: str = ""
    # Confidence ceiling for semantic (non-exact) matches. Semantic hits are
    # advisory and must never claim exact-match certainty.
    semantic_max_confidence: float = Field(default=0.75, ge=0.0, le=1.0)


settings = Settings()
