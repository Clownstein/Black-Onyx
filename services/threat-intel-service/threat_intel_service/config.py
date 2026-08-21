from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="THREAT_INTEL_", extra="ignore")

    database_url: str = "postgresql+psycopg://anomaly:anomaly@localhost:5432/threat_intel"
    host: str = "0.0.0.0"
    port: int = 8098
    # Default enables auth for local/dev; set empty only for explicit open lab use.
    service_api_key: str = "dev-threat-intel-key"
    airgap_mode: bool = False
    taxii_url: str | None = None
    taxii_token: str | None = None
    taxii_username: str | None = None
    taxii_password: str | None = None
    taxii_page_limit: int = 100
    taxii_max_pages: int = 100
    misp_url: str | None = None
    misp_key: str | None = None
    misp_page_size: int = 500
    misp_max_pages: int = 100
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
    # Confidence ceiling for semantic (non-exact) matches. Semantic hits are
    # advisory and must never claim exact-match certainty.
    semantic_max_confidence: float = 0.75


settings = Settings()
