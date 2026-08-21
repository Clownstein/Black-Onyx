from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(extra="ignore")

    database_url: str = Field(
        default="postgresql+psycopg://anomaly:anomaly@localhost:5432/incident_api",
        validation_alias=AliasChoices("INCIDENT_API_DATABASE_URL", "DATABASE_URL"),
    )
    host: str = Field(default="0.0.0.0", validation_alias="INCIDENT_API_HOST")
    port: int = Field(default=8083, validation_alias="INCIDENT_API_PORT")
    oidc_issuer: str = Field(default="", validation_alias="OIDC_ISSUER")
    oidc_audience: str = Field(default="", validation_alias="OIDC_AUDIENCE")
    oidc_disabled: bool = Field(default=False, validation_alias="OIDC_DISABLED")
    oidc_jwks_url: str = Field(default="", validation_alias="OIDC_JWKS_URL")
    oidc_hs_secret: str = Field(default="", validation_alias="OIDC_HS_SECRET")
    service_api_key: str = Field(default="", validation_alias="INCIDENT_API_SERVICE_KEY")
    deployment_consumer_enabled: bool = Field(
        default=False,
        validation_alias="INCIDENT_API_DEPLOYMENT_CONSUMER_ENABLED",
    )
    kafka_brokers: str = Field(
        default="localhost:19092",
        validation_alias="INCIDENT_API_KAFKA_BROKERS",
    )
    deployment_topic: str = Field(
        default="deployments.raw",
        validation_alias="INCIDENT_API_DEPLOYMENT_TOPIC",
    )
    deployment_dlq_topic: str = Field(
        default="deployments.raw.dlq",
        validation_alias="INCIDENT_API_DEPLOYMENT_DLQ_TOPIC",
    )
    deployment_consumer_group: str = Field(
        default="incident-api-deployments",
        validation_alias="INCIDENT_API_DEPLOYMENT_CONSUMER_GROUP",
    )
    use_sqlite: bool = Field(
        default=False,
        validation_alias=AliasChoices("INCIDENT_API_USE_SQLITE", "use_sqlite"),
    )
    sqlite_path: str = Field(
        default=":memory:",
        validation_alias=AliasChoices("INCIDENT_API_SQLITE_PATH", "sqlite_path"),
    )
    opensearch_url: str = Field(
        default="http://localhost:9200",
        validation_alias=AliasChoices("OPENSEARCH_URL", "INCIDENT_API_OPENSEARCH_URL"),
    )
    opensearch_username: str = Field(
        default="",
        validation_alias=AliasChoices(
            "OPENSEARCH_USERNAME", "INCIDENT_API_OPENSEARCH_USERNAME"
        ),
    )
    opensearch_password: str = Field(
        default="",
        validation_alias=AliasChoices(
            "OPENSEARCH_PASSWORD", "INCIDENT_API_OPENSEARCH_PASSWORD"
        ),
    )
    opensearch_verify_tls: bool = Field(
        default=True,
        validation_alias=AliasChoices(
            "OPENSEARCH_VERIFY_TLS", "INCIDENT_API_OPENSEARCH_VERIFY_TLS"
        ),
    )
    opensearch_indexing: bool = Field(
        default=True,
        validation_alias=AliasChoices(
            "INCIDENT_API_OPENSEARCH_INDEXING",
            "OPENSEARCH_INDEXING",
        ),
    )
    allow_demo_keys: bool = Field(
        default=False,
        validation_alias=AliasChoices("ALLOW_DEMO_KEYS", "INCIDENT_API_ALLOW_DEMO_KEYS"),
    )
    vector_search_enabled: bool = Field(
        default=False,
        validation_alias=AliasChoices(
            "VECTOR_SEARCH_ENABLED", "INCIDENT_API_VECTOR_SEARCH_ENABLED"
        ),
    )
    federated_hunt_enabled: bool = Field(
        default=False,
        validation_alias=AliasChoices(
            "FEDERATED_HUNT_ENABLED", "INCIDENT_API_FEDERATED_HUNT_ENABLED"
        ),
    )
    qdrant_url: str = Field(
        default="",
        validation_alias=AliasChoices("QDRANT_URL", "INCIDENT_API_QDRANT_URL"),
    )
    embedding_service_url: str = Field(
        default="",
        validation_alias=AliasChoices(
            "EMBEDDING_SERVICE_URL",
            "INCIDENT_API_EMBEDDING_SERVICE_URL",
        ),
    )
    threat_intel_url: str = Field(
        default="http://localhost:8098",
        validation_alias=AliasChoices("THREAT_INTEL_URL", "INCIDENT_API_THREAT_INTEL_URL"),
    )
    threat_intel_service_key: str = Field(
        default="dev-threat-intel-key",
        validation_alias=AliasChoices(
            "THREAT_INTEL_SERVICE_KEY",
            "INCIDENT_API_THREAT_INTEL_SERVICE_KEY",
        ),
    )
    minio_endpoint: str = Field(
        default="http://localhost:9000",
        validation_alias=AliasChoices("MINIO_ENDPOINT", "INCIDENT_API_MINIO_ENDPOINT"),
    )
    minio_access_key: str = Field(
        default="minioadmin",
        validation_alias=AliasChoices("MINIO_ACCESS_KEY", "INCIDENT_API_MINIO_ACCESS_KEY"),
    )
    minio_secret_key: str = Field(
        default="minioadmin",
        validation_alias=AliasChoices("MINIO_SECRET_KEY", "INCIDENT_API_MINIO_SECRET_KEY"),
    )
    minio_region: str = Field(
        default="us-east-1",
        validation_alias=AliasChoices("MINIO_REGION", "INCIDENT_API_MINIO_REGION"),
    )


settings = Settings()
