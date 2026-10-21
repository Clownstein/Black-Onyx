from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(extra="ignore")

    database_url: str = Field(
        default="postgresql+psycopg://anomaly:anomaly@localhost:5432/smoke",
        validation_alias="SMOKE_DATABASE_URL",
    )
    kafka_bootstrap_servers: str = Field(
        default="localhost:19092",
        validation_alias="KAFKA_BOOTSTRAP_SERVERS",
    )
    topic: str = Field(default="logs.raw", validation_alias="SMOKE_TOPIC")
    group_id: str = Field(default="smoke-consumer", validation_alias="SMOKE_GROUP_ID")
    host: str = Field(default="0.0.0.0", validation_alias="SMOKE_HOST")
    port: int = Field(default=8082, validation_alias="SMOKE_PORT")
    consumer_poll_seconds: float = Field(
        default=1.0,
        validation_alias="SMOKE_CONSUMER_POLL_SECONDS",
    )


settings = Settings()
