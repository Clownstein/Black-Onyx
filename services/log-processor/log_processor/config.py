from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="LOG_PROCESSOR_", extra="ignore")

    kafka_brokers: str = "localhost:19092"
    topic_raw: str = "logs.raw"
    topic_features: str = "logs.features"
    topic_dlq: str = "logs.features.dlq"
    group_id: str = "log-processor"
    processor_version: str = "1.0.0"
    feature_version: str = "1.0"
    host: str = "0.0.0.0"
    port: int = 8082

    max_sequence_length: int = 128
    sequence_stride: int = 32
    min_sequence_length: int = 4
    max_duration_seconds: int = 900
    inactivity_timeout_seconds: int = 300


settings = Settings()
