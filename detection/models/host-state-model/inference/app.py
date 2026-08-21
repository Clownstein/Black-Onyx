"""FastAPI inference service for the host-state pass-through model."""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from host_state_model.scorer import HostStateScorer


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="HOST_STATE_MODEL_", extra="ignore")

    host: str = "0.0.0.0"
    port: int = 8104


settings = Settings()
scorer = HostStateScorer()
app = FastAPI(title="Host State Model Inference", version=scorer.model_version)


class PredictRequest(BaseModel):
    model_config = {"protected_namespaces": ()}

    request_id: str
    tenant_id: str
    model_name: str = "host-state-model"
    feature_version: str = "host-state.features.v1"
    items: list[dict[str, Any]] = Field(min_length=1)


@app.get("/health/live")
def live() -> dict[str, str]:
    return {"status": "alive"}


@app.get("/health/ready")
def ready() -> dict[str, Any]:
    return scorer.health()


@app.post("/v1/predict")
def predict(body: PredictRequest) -> dict[str, Any]:
    if body.model_name not in {scorer.model_name, "host-state", "host-state-model"}:
        raise HTTPException(status_code=400, detail="unsupported model_name")
    return scorer.predict(body.model_dump())


def run() -> None:
    import uvicorn

    uvicorn.run("inference.app:app", host=settings.host, port=settings.port, reload=False)


if __name__ == "__main__":
    run()
