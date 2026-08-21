from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="IDS_PROCESSOR_", extra="ignore")

    host: str = "0.0.0.0"
    # Compose/host port 8100 — 8099 is reserved for firewall-processor.
    port: int = 8100
    kafka_brokers: str = "localhost:19092"
    topic_raw: str = "suricata.raw"
    topic_findings: str = "findings.network"
    topic_dlq: str = "suricata.raw.dlq"
    consumer_group: str = "ids-processor"
    enable_kafka: bool = True
    publish_findings: bool = True
    minio_endpoint: str = "http://localhost:9000"
    minio_access_key: str = "minioadmin"
    minio_secret_key: str = "minioadmin"
    minio_bucket: str = "anomaly-pcap"
    minio_region: str = "us-east-1"


settings = Settings()
