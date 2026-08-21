from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="METRICS_PROCESSOR_", extra="ignore")

    host: str = "0.0.0.0"
    port: int = 8092
    kafka_brokers: str = "localhost:19092"
    topic_raw: str = "metrics.raw"
    topic_features: str = "metrics.features"
    topic_dlq: str = "metrics.raw.dlq"
    consumer_group: str = "metrics-processor"
    enable_kafka: bool = True
    profile: str = "web_service_v1"
    sample_interval_seconds: int = 60
    window_length: int = 60
    stride: int = 5
    max_missing_fraction: float = 0.10


settings = Settings()
