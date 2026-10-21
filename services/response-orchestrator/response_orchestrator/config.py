from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="RESPONSE_ORCHESTRATOR_", extra="ignore")

    host: str = "0.0.0.0"
    port: int = 8111
    database_url: str = "sqlite+pysqlite:///:memory:"
    # Fail closed unless deployment configuration supplies an S2S key.
    api_key: str = ""
    # Separate key required to flip dry_run requests to live execution on approve.
    approver_api_key: str = ""
    dry_run_default: bool = True
    execution_uncertain_after_seconds: int = Field(default=600, ge=60, le=86_400)
    playbooks_dir: str = ""
    pfsense_api_url: str = ""
    pfsense_api_key: str = ""
    edr_api_url: str = ""
    edr_api_key: str = ""
    # "wazuh" routes isolate_host to Wazuh active response instead of EDR_API_URL.
    edr_provider: str = ""
    wazuh_api_url: str = ""
    wazuh_api_user: str = ""
    wazuh_api_password: str = ""
    wazuh_api_ca_file: str = ""
    wazuh_api_verify_tls: bool = True
    wazuh_ar_command: str = "!black-onyx-isolate"
    wazuh_ar_command_windows: str = "!black-onyx-isolate.cmd"
    # Comma-separated IPs/CIDRs the isolated host keeps reaching (Wazuh manager, jump host).
    wazuh_isolation_allow: str = ""
    capture_api_url: str = ""
    capture_api_key: str = ""
    dns_rpz_url: str = ""
    dns_rpz_key: str = ""


settings = Settings()
