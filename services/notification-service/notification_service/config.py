from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(extra="ignore")

    host: str = "0.0.0.0"
    port: int = 8086
    database_url: str = Field(
        default="sqlite+pysqlite:///:memory:",
        validation_alias=AliasChoices("NOTIFICATION_DATABASE_URL", "DATABASE_URL"),
    )
    notification_webhook_url: str = ""
    notification_webhook_secret: str = "dev-webhook-secret"
    # Empty disables auth (dev). Set NOTIFICATION_API_KEY to require X-API-Key.
    notification_api_key: str = ""
    webhook_max_retries: int = 3
    webhook_retry_backoff_seconds: float = 0.05
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_from: str = "black-onyx-detection@localhost"
    smtp_starttls: bool = True


settings = Settings()
