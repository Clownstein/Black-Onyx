from __future__ import annotations

from pathlib import Path
from typing import Any
import os

from fastapi import FastAPI, HTTPException, Query, Response, status
from pydantic import BaseModel, Field

from code_model.scorer import ChangeRiskModel

ARTIFACT_DIR = Path(__file__).resolve().parents[1] / "artifacts"

app = FastAPI(title="Code Model Inference", version="2.1.0")
_model = ChangeRiskModel()
_load_error: str | None = None


def _load_package(package_dir: Path) -> ChangeRiskModel:
    """Loader for orchestrator-managed signed packages (re-verified on load)."""
    model = ChangeRiskModel()
    model.load(package_dir, signing_key=os.getenv("MODEL_SERVING_SIGNING_KEY")
               or os.getenv("TRAINING_ARTIFACT_SIGNING_KEY")
               or os.getenv("CODE_MODEL_ARTIFACT_SIGNING_KEY", ""))
    if model.model is None:
        raise ValueError("Signed code package has no loadable weights")
    return model


def _configure_serving():
    from black_onyx_model_package.serving import configure_from_env

    return configure_from_env("code-model", _load_package)


serving_registry, serving_sync = _configure_serving()


def _active(alias: str | None) -> ChangeRiskModel:
    """Signed package serving ``alias``; the baked artifact is dev-only."""
    if serving_registry is not None:
        slot = serving_registry.get(alias)
        if slot is None:
            raise HTTPException(status_code=503, detail="No signed code model package is loaded yet")
        return slot.model
    return _model


@app.get("/v1/serving")
def serving_status() -> dict[str, Any]:
    if serving_registry is None:
        return {"enabled": False, "baked_version": _model.model_version}
    return {"enabled": True, **serving_registry.status()}


@app.on_event("startup")
def start_serving_sync() -> None:
    if serving_sync is not None:
        serving_sync.start()


@app.on_event("startup")
def startup() -> None:
    global _load_error
    _model.model = None
    if (ARTIFACT_DIR / "model.joblib").is_file():
        try:
            _model.load(ARTIFACT_DIR, signing_key=os.getenv("CODE_MODEL_ARTIFACT_SIGNING_KEY", ""))
            _load_error = None
        except (OSError, ValueError, KeyError) as exc:
            _model.model = None
            _load_error = str(exc)
    else:
        _load_error = "A signed code model package is required"


class PredictRequest(BaseModel):
    diff_text: str = ""
    files_changed: list[str] = Field(default_factory=list)
    diff_stats: dict[str, Any] = Field(default_factory=dict)
    scanner_findings: list[dict[str, Any]] = Field(default_factory=list)
    text_features: dict[str, Any] = Field(default_factory=dict)
    changed_symbols: list[dict[str, Any]] = Field(default_factory=list)


@app.get("/health/live")
def live() -> dict[str, str]:
    return {"status": "alive"}


@app.get("/health/ready")
def ready(response: Response) -> dict[str, object]:
    try:
        artifact_loaded = _active("champion").model is not None
    except HTTPException:
        artifact_loaded = False
    if not artifact_loaded:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return {
        "status": "ready" if artifact_loaded else "not_ready",
        "artifact_loaded": artifact_loaded,
        "artifact_error": _load_error if not artifact_loaded else None,
        "advisory_only": True,
    }


@app.post("/v1/predict")
def predict(req: PredictRequest, alias: str | None = Query(default=None)) -> dict[str, Any]:
    active = _active(alias if isinstance(alias, str) else None)
    if active.model is None:
        raise HTTPException(status_code=503, detail="A trained code model artifact is required")
    payload = req.model_dump()
    if not payload.get("diff_text") and payload.get("text_features"):
        payload["diff_text"] = payload["text_features"].get("diff_text", "")
    result = active.predict(payload)
    return {
        "risk_score": result["risk_score"],
        "risk_categories": result["risk_categories"],
        "evidence": result["evidence"],
        "model_version": result["model_version"],
        "model_name": result["model_name"],
        "meta": {"advisory_only": True},
    }


def run() -> None:
    import uvicorn

    uvicorn.run("inference.app:app", host="0.0.0.0", port=8103, reload=False)


if __name__ == "__main__":
    run()
