from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="RESPONSE_ORCHESTRATOR_", extra="ignore")

    host: str = "0.0.0.0"
    port: int = 8111
    database_url: str = "sqlite+pysqlite:///:memory:"
    api_key: str = "dev-response-key"
    # Separate key required to flip dry_run requests to live execution on approve.
    approver_api_key: str = ""
    dry_run_default: bool = True
    playbooks_dir: str = ""
    pfsense_api_url: str = ""
    pfsense_api_key: str = ""
    edr_api_url: str = ""
    edr_api_key: str = ""
    capture_api_url: str = ""
    capture_api_key: str = ""
    dns_rpz_url: str = ""
    dns_rpz_key: str = ""


settings = Settings()
