from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(extra="ignore", populate_by_name=True)

    host: str = Field(
        default="0.0.0.0",
        validation_alias=AliasChoices("INTEGRATION_HUB_HOST", "HOST"),
    )
    port: int = Field(
        default=8105,
        validation_alias=AliasChoices("INTEGRATION_HUB_PORT", "PORT"),
    )
    database_url: str = Field(
        default="sqlite+pysqlite:///:memory:",
        validation_alias=AliasChoices(
            "INTEGRATION_HUB_DATABASE_URL",
            "DATABASE_URL",
        ),
    )
    # Default enables auth; set empty only for explicit open lab use.
    api_key: str = Field(
        default="dev-integration-key",
        validation_alias=AliasChoices(
            "INTEGRATION_HUB_API_KEY",
            "INTEGRATION_API_KEY",
        ),
    )
    threat_intel_service_key: str = Field(
        default="dev-threat-intel-key",
        validation_alias=AliasChoices(
            "INTEGRATION_HUB_THREAT_INTEL_SERVICE_KEY",
            "THREAT_INTEL_SERVICE_KEY",
        ),
    )
    thehive_url: str = Field(
        default="",
        validation_alias=AliasChoices("THEHIVE_URL", "INTEGRATION_HUB_THEHIVE_URL"),
    )
    thehive_key: str = Field(
        default="",
        validation_alias=AliasChoices("THEHIVE_KEY", "INTEGRATION_HUB_THEHIVE_KEY"),
    )
    threat_intel_url: str = Field(
        default="http://localhost:8098",
        validation_alias=AliasChoices(
            "INTEGRATION_HUB_THREAT_INTEL_URL",
            "THREAT_INTEL_URL",
        ),
    )
    threat_intel_timeout_seconds: float = Field(
        default=5.0,
        validation_alias=AliasChoices("INTEGRATION_HUB_THREAT_INTEL_TIMEOUT_SECONDS"),
    )
    kev_score_boost: float = Field(
        default=0.25,
        validation_alias=AliasChoices("INTEGRATION_HUB_KEV_SCORE_BOOST"),
    )
    siem_default_format: str = Field(
        default="json",
        validation_alias=AliasChoices("INTEGRATION_HUB_SIEM_DEFAULT_FORMAT"),
    )
    siem_device_vendor: str = Field(
        default="BlackOnyx",
        validation_alias=AliasChoices("INTEGRATION_HUB_SIEM_DEVICE_VENDOR"),
    )
    siem_device_product: str = Field(
        default="integration-hub",
        validation_alias=AliasChoices("INTEGRATION_HUB_SIEM_DEVICE_PRODUCT"),
    )
    siem_device_version: str = Field(
        default="0.1.0",
        validation_alias=AliasChoices("INTEGRATION_HUB_SIEM_DEVICE_VERSION"),
    )
    data_dir: str = Field(
        default="data",
        validation_alias=AliasChoices("INTEGRATION_HUB_DATA_DIR"),
    )
    playbooks_dir: str = Field(
        default="",
        validation_alias=AliasChoices("INTEGRATION_HUB_PLAYBOOKS_DIR", "PLAYBOOKS_DIR"),
    )
    pfsense_api_url: str = Field(
        default="",
        validation_alias=AliasChoices("PFSENSE_API_URL", "INTEGRATION_HUB_PFSENSE_API_URL"),
    )
    pfsense_api_key: str = Field(
        default="",
        validation_alias=AliasChoices("PFSENSE_API_KEY", "INTEGRATION_HUB_PFSENSE_API_KEY"),
    )
    edr_api_url: str = Field(
        default="",
        validation_alias=AliasChoices("EDR_API_URL", "INTEGRATION_HUB_EDR_API_URL"),
    )
    edr_api_key: str = Field(
        default="",
        validation_alias=AliasChoices("EDR_API_KEY", "INTEGRATION_HUB_EDR_API_KEY"),
    )
    velociraptor_url: str = Field(
        default="",
        validation_alias=AliasChoices("VELOCIRAPTOR_URL", "INTEGRATION_HUB_VELOCIRAPTOR_URL"),
    )
    velociraptor_key: str = Field(
        default="",
        validation_alias=AliasChoices("VELOCIRAPTOR_KEY", "INTEGRATION_HUB_VELOCIRAPTOR_KEY"),
    )
    incident_api_url: str = Field(
        default="http://localhost:8083",
        validation_alias=AliasChoices(
            "INTEGRATION_HUB_INCIDENT_API_URL",
            "INCIDENT_API_URL",
        ),
    )
    incident_api_service_key: str = Field(
        default="",
        validation_alias=AliasChoices(
            "INTEGRATION_HUB_INCIDENT_API_SERVICE_KEY",
            "INCIDENT_API_SERVICE_KEY",
        ),
    )
    incident_api_timeout_seconds: float = Field(
        default=10.0,
        validation_alias=AliasChoices("INTEGRATION_HUB_INCIDENT_API_TIMEOUT_SECONDS"),
    )
    persist_findings: bool = Field(
        default=True,
        validation_alias=AliasChoices("INTEGRATION_HUB_PERSIST_FINDINGS"),
    )
    response_orchestrator_url: str = Field(
        default="http://localhost:8111",
        validation_alias=AliasChoices(
            "INTEGRATION_HUB_RESPONSE_ORCHESTRATOR_URL",
            "RESPONSE_ORCHESTRATOR_URL",
        ),
    )
    response_orchestrator_api_key: str = Field(
        default="dev-response-key",
        validation_alias=AliasChoices(
            "INTEGRATION_HUB_RESPONSE_ORCHESTRATOR_API_KEY",
            "RESPONSE_ORCHESTRATOR_API_KEY",
        ),
    )
    response_orchestrator_timeout_seconds: float = Field(
        default=10.0,
        validation_alias=AliasChoices(
            "INTEGRATION_HUB_RESPONSE_ORCHESTRATOR_TIMEOUT_SECONDS"
        ),
    )


settings = Settings()
