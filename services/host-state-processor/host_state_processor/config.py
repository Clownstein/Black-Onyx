from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="HOST_STATE_PROCESSOR_", extra="ignore")

    host: str = "0.0.0.0"
    api_key: str = ""
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
    heartbeat_tenant_ids: str = ""
    heartbeat_timeout_seconds: float = 5.0
    asset_registry_url: str = "http://asset-registry:8081"
    asset_registry_service_key: str = ""

    @model_validator(mode="after")
    def validate_heartbeat_configuration(self) -> "Settings":
        if self.enable_heartbeat:
            if not any(value.strip() for value in self.heartbeat_tenant_ids.split(",")):
                raise ValueError("heartbeat tenant IDs are required when heartbeat is enabled")
            if not self.asset_registry_service_key:
                raise ValueError("asset registry service key is required when heartbeat is enabled")
        return self


settings = Settings()
