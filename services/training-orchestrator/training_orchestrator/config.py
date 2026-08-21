from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="TRAINING_ORCHESTRATOR_", extra="ignore")

    database_url: str = "sqlite+pysqlite:///:memory:"
    host: str = "0.0.0.0"
    port: int = 8090
    package_output_dir: str = "model-package"
    artifact_signing_key: str = "dev-signing-key-change-me"
    repo_root: str = ""
    training_timeout_seconds: int = 120


settings = Settings()
