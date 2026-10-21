from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(extra="ignore")

    host: str = "0.0.0.0"
    port: int = 8091
    api_key: str = ""
    canary_percent: int = 10
    log_model_url: str = "http://127.0.0.1:8090"
    network_model_url: str = "http://127.0.0.1:8101"
    metrics_model_url: str = "http://127.0.0.1:8102"
    code_model_url: str = "http://127.0.0.1:8103"
    host_state_model_url: str = "http://127.0.0.1:8104"
    request_timeout_seconds: float = 5.0
    shadow_timeout_seconds: float = 2.0
    # Serving state from the training orchestrator: canary traffic is routed
    # only when a canary package is confirmed loaded, and responses are
    # checked against the version each alias should be serving.
    training_orchestrator_url: str = ""
    training_api_key: str = ""
    serving_tenant: str = "default"
    serving_state_ttl_seconds: float = 15.0
    serving_state_max_stale_seconds: float = 30.0


settings = Settings()
