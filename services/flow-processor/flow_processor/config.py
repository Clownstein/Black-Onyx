from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="FLOW_PROCESSOR_", extra="ignore")

    host: str = "0.0.0.0"
    # Keep the standalone default aligned with Compose and Helm. 8091 belongs
    # to model-gateway, so sharing it makes local service runs collide.
    port: int = 8094
    kafka_brokers: str = "localhost:19092"
    topic_raw: str = "network.raw"
    topic_zeek_raw: str = "zeek.raw"
    topic_dns_raw: str = "dns.raw"
    topic_features: str = "network.features"
    topic_dlq: str = "network.raw.dlq"
    consumer_group: str = "flow-processor"
    enable_kafka: bool = True
    consume_zeek_raw: bool = True
    consume_dns_raw: bool = True
    ip_hash_salt: str = "black-onyx-detection-ip-salt"
    window_duration_seconds: int = 300
    max_events: int = 256
    stride_events: int = 64
    minimum_events: int = 4


settings = Settings()
