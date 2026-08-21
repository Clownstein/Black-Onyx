"""FastAPI inference service for the log anomaly model."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Response, status
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from log_model.scorer import LogAnomalyScorer


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="LOG_MODEL_", extra="ignore")

    artifacts_dir: Path = Path(__file__).resolve().parents[1] / "artifacts"
    host: str = "0.0.0.0"
    port: int = 8090


settings = Settings()
scorer = LogAnomalyScorer(artifacts_dir=settings.artifacts_dir)
app = FastAPI(title="Log Model Inference", version=scorer.model_version)


class PredictRequest(BaseModel):
    model_config = {"protected_namespaces": ()}

    request_id: str
    tenant_id: str
    model_name: str = "log-transformer"
    feature_version: str = "1.0"
    items: list[dict[str, Any]] = Field(min_length=1)


@app.get("/health/live")
def live() -> dict[str, str]:
    return {"status": "alive"}


@app.get("/health/ready")
def ready(response: Response) -> dict[str, Any]:
    health = scorer.health()
    if health["status"] != "ready":
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return health


@app.post("/v1/predict")
def predict(body: PredictRequest) -> dict[str, Any]:
    if scorer.backend not in {"onnx", "pytorch"}:
        raise HTTPException(status_code=503, detail="A trained log model artifact is required")
    if body.model_name not in {scorer.model_name, "log-model", "log-transformer"}:
        raise HTTPException(status_code=400, detail="unsupported model_name")
    try:
        return scorer.predict(body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


def run() -> None:
    import uvicorn

    uvicorn.run("inference.app:app", host=settings.host, port=settings.port, reload=False)


if __name__ == "__main__":
    run()
