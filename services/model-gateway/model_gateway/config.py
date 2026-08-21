from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(extra="ignore")

    host: str = "0.0.0.0"
    port: int = 8091
    canary_percent: int = 10
    log_model_url: str = "http://127.0.0.1:8090"
    network_model_url: str = "http://127.0.0.1:8101"
    metrics_model_url: str = "http://127.0.0.1:8102"
    code_model_url: str = "http://127.0.0.1:8103"
    host_state_model_url: str = "http://127.0.0.1:8104"
    request_timeout_seconds: float = 5.0
    shadow_timeout_seconds: float = 2.0


settings = Settings()
