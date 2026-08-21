from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="HOST_STATE_PROCESSOR_", extra="ignore")

    host: str = "0.0.0.0"
    port: int = 8097
    kafka_brokers: str = "localhost:19092"
    topic_raw: str = "host-state.raw"
    topic_features: str = "host-state.features"
    topic_dlq: str = "host-state.raw.dlq"
    topic_findings: str = "findings.host-state"
    consumer_group: str = "host-state-processor"
    enable_kafka: bool = True
    publish_findings: bool = True

    # Telemetry-gap (heartbeat) detection. Off by default so existing
    # deployments keep their current behavior; the self-monitor compose profile
    # turns it on.
    enable_heartbeat: bool = False
    heartbeat_interval_seconds: int = 60
    stale_after_seconds: int = 900
    heartbeat_tenant_ids: str = "tenant-demo"
    heartbeat_timeout_seconds: float = 5.0
    asset_registry_url: str = "http://asset-registry:8081"
    asset_registry_service_key: str = ""


settings = Settings()
