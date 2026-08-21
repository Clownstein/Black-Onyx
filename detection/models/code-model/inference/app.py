from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Response, status
from pydantic import BaseModel, Field

from code_model.scorer import ChangeRiskModel

ARTIFACT_DIR = Path(__file__).resolve().parents[1] / "artifacts"

app = FastAPI(title="Code Model Inference", version="2.1.0")
_model = ChangeRiskModel()


@app.on_event("startup")
def startup() -> None:
    if (ARTIFACT_DIR / "model.joblib").is_file():
        _model.load(ARTIFACT_DIR)


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
    artifact_loaded = (ARTIFACT_DIR / "model.joblib").is_file() and _model.model is not None
    if not artifact_loaded:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return {
        "status": "ready" if artifact_loaded else "not_ready",
        "artifact_loaded": artifact_loaded,
        "advisory_only": True,
    }


@app.post("/v1/predict")
def predict(req: PredictRequest) -> dict[str, Any]:
    if _model.model is None:
        raise HTTPException(status_code=503, detail="A trained code model artifact is required")
    payload = req.model_dump()
    if not payload.get("diff_text") and payload.get("text_features"):
        payload["diff_text"] = payload["text_features"].get("diff_text", "")
    result = _model.predict(payload)
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
