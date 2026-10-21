from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="TRAINING_ORCHESTRATOR_", extra="ignore")

    database_url: str = "sqlite+pysqlite:///:memory:"
    host: str = "0.0.0.0"
    port: int = 8090
    package_output_dir: str = "model-package"
    api_key: str = ""
    environment: str = "development"
    artifact_signing_key: str = ""
    repo_root: str = ""
    allowed_dataset_roots: str = ""
    max_dataset_bytes: int = 10 * 1024 * 1024 * 1024
    training_timeout_seconds: int = 120
    worker_poll_seconds: float = 2.0
    worker_heartbeat_seconds: float = 30.0
    worker_lease_seconds: int = 300
    worker_max_attempts: int = 3
    allow_synthetic_training: bool = False
    allow_synchronous_training: bool = False
    # Promotion/rollback commit only after model replicas confirm they serve
    # the signed package (see training_orchestrator.serving).
    serving_confirmation_required: bool = True
    serving_confirm_timeout_seconds: float = 180.0
    serving_confirm_poll_seconds: float = 2.0
    serving_instance_ttl_seconds: int = 90
    serving_min_instances: int = 1
    serving_restore_timeout_seconds: float = 180.0

    def allowed_dataset_root_list(self) -> list[Path]:
        return [
            Path(value.strip()).resolve()
            for value in self.allowed_dataset_roots.split(",")
            if value.strip()
        ]


settings = Settings()
