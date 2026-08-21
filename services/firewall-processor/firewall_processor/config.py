from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="FIREWALL_PROCESSOR_", extra="ignore")

    host: str = "0.0.0.0"
    port: int = 8099
    kafka_brokers: str = "localhost:19092"
    topic_raw: str = "firewall.raw"
    topic_features: str = "firewall.features"
    topic_dlq: str = "firewall.raw.dlq"
    topic_findings: str = "findings.firewall"
    consumer_group: str = "firewall-processor"
    enable_kafka: bool = True
    publish_findings: bool = True
    # Sliding window for deny_spike aggregation (seconds).
    deny_window_seconds: int = 300
    deny_spike_threshold: int = 20
    change_window_start_hour_utc: int = 9
    change_window_end_hour_utc: int = 17


settings = Settings()
