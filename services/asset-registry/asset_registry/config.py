from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(extra="ignore")

    database_url: str = Field(
        default="postgresql+psycopg://anomaly:anomaly@localhost:5432/asset_registry",
        validation_alias=AliasChoices("ASSET_REGISTRY_DATABASE_URL", "DATABASE_URL"),
    )
    host: str = Field(default="0.0.0.0", validation_alias="ASSET_REGISTRY_HOST")
    port: int = Field(default=8081, validation_alias="ASSET_REGISTRY_PORT")
    oidc_issuer: str = Field(default="", validation_alias="OIDC_ISSUER")
    oidc_audience: str = Field(default="", validation_alias="OIDC_AUDIENCE")
    oidc_disabled: bool = Field(default=False, validation_alias="OIDC_DISABLED")
    oidc_jwks_url: str = Field(default="", validation_alias="OIDC_JWKS_URL")
    oidc_hs_secret: str = Field(default="", validation_alias="OIDC_HS_SECRET")
    service_api_key: str = Field(default="", validation_alias="ASSET_REGISTRY_SERVICE_KEY")
    incident_api_url: str = Field(
        default="http://localhost:8083",
        validation_alias="ASSET_REGISTRY_INCIDENT_API_URL",
    )
    incident_api_service_key: str = Field(
        default="",
        validation_alias="ASSET_REGISTRY_INCIDENT_API_SERVICE_KEY",
    )
    dependency_timeout_seconds: float = Field(
        default=3.0,
        gt=0.0,
        validation_alias="ASSET_REGISTRY_DEPENDENCY_TIMEOUT_SECONDS",
    )


settings = Settings()
