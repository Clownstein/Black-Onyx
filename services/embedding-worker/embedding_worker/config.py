from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="EMBEDDING_",
        extra="ignore",
        populate_by_name=True,
    )

    host: str = "0.0.0.0"
    port: int = 8115
    kafka_brokers: str = "localhost:19092"
    finding_topics: str = (
        "findings.logs,findings.code,findings.network,findings.metrics,"
        "findings.host-state,findings.firewall,findings.malware"
    )
    topic_dlq: str = "findings.embedding.dlq"
    consumer_group: str = "embedding-worker"
    enable_kafka: bool = True

    # Vector search feature flag + Qdrant endpoint (shared env names across services).
    vector_search_enabled: bool = Field(
        default=False,
        validation_alias=AliasChoices("VECTOR_SEARCH_ENABLED", "EMBEDDING_VECTOR_SEARCH_ENABLED"),
    )
    qdrant_url: str = Field(
        default="http://localhost:6333",
        validation_alias=AliasChoices("QDRANT_URL", "EMBEDDING_QDRANT_URL"),
    )
    qdrant_api_key: str = Field(
        default="",
        validation_alias=AliasChoices("QDRANT_API_KEY", "EMBEDDING_QDRANT_API_KEY"),
    )

    embed_model: str = "cisco-ai/SecureBERT2.0-biencoder"
    embed_version: str = "1"

    findings_collection: str = "findings_v1"


settings = Settings()
