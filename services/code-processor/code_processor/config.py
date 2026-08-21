from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="CODE_PROCESSOR_", extra="ignore")

    host: str = "0.0.0.0"
    port: int = 8093
    kafka_brokers: str = "localhost:19092"
    topic_raw: str = "code.raw"
    topic_features: str = "code.features"
    topic_findings: str = "code.findings"
    topic_dlq: str = "code.raw.dlq"
    consumer_group: str = "code-processor"
    enable_kafka: bool = True
    webhook_secret: str = "dev-webhook-secret"
    heuristic_enabled: bool = False
    semgrep_enabled: bool = True
    codeql_enabled: bool = False
    codeql_cli_path: str = "/opt/codeql/codeql"
    codeql_timeout_seconds: int = 300
    codeql_max_source_bytes: int = 50_000_000
    codeql_threads: int = 1
    codeql_ram_mb: int = 1024


settings = Settings()
