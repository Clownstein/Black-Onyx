"""FastAPI inference service for the log anomaly model."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query, Response, status
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


def _load_package(package_dir: Path) -> LogAnomalyScorer:
    """Loader for orchestrator-managed signed packages (already verified)."""
    loaded = LogAnomalyScorer(artifacts_dir=package_dir)
    if loaded.backend not in {"onnx", "pytorch"}:
        raise ValueError(loaded.load_error or "Signed log package has no loadable weights")
    return loaded


def _configure_serving():
    from black_onyx_model_package.serving import configure_from_env

    return configure_from_env("log-model", _load_package)


serving_registry, serving_sync = _configure_serving()


@app.on_event("startup")
def start_serving_sync() -> None:
    if serving_sync is not None:
        serving_sync.start()


def _scorer_for(alias: str | None) -> tuple[LogAnomalyScorer, str]:
    """Pick the signed package serving ``alias``; the baked artifact is dev-only."""
    if serving_registry is not None:
        slot = serving_registry.get(alias)
        if slot is not None:
            return slot.model, slot.alias
        raise HTTPException(status_code=503, detail="No signed log model package is loaded yet")
    return scorer, "baked"


@app.get("/v1/serving")
def serving_status() -> dict[str, Any]:
    if serving_registry is None:
        return {"enabled": False, "baked_version": scorer.model_version}
    return {"enabled": True, **serving_registry.status()}


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
    if serving_registry is not None:
        slot = serving_registry.get("champion")
        health = slot.model.health() if slot else {"status": "not_ready", "error": "no signed package loaded"}
        health["serving"] = serving_registry.status()
    else:
        health = scorer.health()
    if health["status"] != "ready":
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return health


@app.post("/v1/predict")
def predict(
    body: PredictRequest, response: Response, alias: str | None = Query(default=None),
) -> dict[str, Any]:
    active, served_alias = _scorer_for(alias)
    if active.backend not in {"onnx", "pytorch"}:
        raise HTTPException(status_code=503, detail="A trained log model artifact is required")
    if body.model_name not in {active.model_name, "log-model", "log-transformer"}:
        raise HTTPException(status_code=400, detail="unsupported model_name")
    try:
        result = active.predict(body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    # Headers, not body fields, so the response contract stays unchanged.
    response.headers["X-Served-Alias"] = served_alias
    response.headers["X-Model-Version"] = str(result.get("model_version", ""))
    return result


def run() -> None:
    import uvicorn

    uvicorn.run("inference.app:app", host=settings.host, port=settings.port, reload=False)


if __name__ == "__main__":
    run()
