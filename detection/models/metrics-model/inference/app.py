from __future__ import annotations

from pathlib import Path
from typing import Any

import joblib
from black_onyx_calibration import Calibrator, load_calibrator
from fastapi import FastAPI, HTTPException, Response, status
from pydantic import BaseModel

from metrics_model.model import (
    IsolationForestFallback,
    MultivariateMetricTransformer,
    contributor_errors,
    reconstruction_contributors,
    window_to_tensor,
)

try:
    import onnxruntime as ort
except ImportError:  # pragma: no cover
    ort = None

ARTIFACT_DIR = Path(__file__).resolve().parents[1] / "artifacts"
ONNX_PATH = ARTIFACT_DIR / "metrics_model.onnx"
PT_PATH = ARTIFACT_DIR / "metrics_model.pt"
IFOREST_PATH = ARTIFACT_DIR / "isolation_forest.joblib"
CALIB_PATH = ARTIFACT_DIR / "calibration.json"

app = FastAPI(title="Metrics Model Inference", version="1.2.0")
_session = None
_torch_model: MultivariateMetricTransformer | None = None
_iforest: IsolationForestFallback | None = None
_calibrator: Calibrator = Calibrator()


def _load() -> None:
    global _session, _torch_model, _iforest, _calibrator
    _calibrator = load_calibrator(CALIB_PATH)
    if IFOREST_PATH.is_file():
        _iforest = joblib.load(IFOREST_PATH)
    if ONNX_PATH.is_file() and ort is not None:
        _session = ort.InferenceSession(str(ONNX_PATH), providers=["CPUExecutionProvider"])
        return
    if PT_PATH.is_file():
        import torch

        _torch_model = MultivariateMetricTransformer()
        state = torch.load(PT_PATH, map_location="cpu", weights_only=True)
        try:
            _torch_model.load_state_dict(state)
            _torch_model.eval()
        except Exception:  # noqa: BLE001 — older classifier-only checkpoints
            _torch_model = None


@app.on_event("startup")
def startup() -> None:
    _load()


class PredictRequest(BaseModel):
    values: dict[str, list[float]] = {}
    missingness: dict[str, list[float]] = {}
    profile: str = "web_service_v1"
    missing_fraction: float | None = None


@app.get("/health/live")
def live() -> dict[str, str]:
    return {"status": "alive"}


@app.get("/health/ready")
def ready(response: Response) -> dict[str, object]:
    mode = "heuristic"
    if _session is not None:
        mode = "onnx"
    elif _torch_model is not None:
        mode = "torch"
    elif _iforest is not None:
        mode = "isolation_forest"
    ready_now = mode in {"onnx", "torch", "isolation_forest"}
    if not ready_now:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return {"status": "ready" if ready_now else "not_ready", "mode": mode}


def _severity(score: float) -> str:
    if score >= 0.93:
        return "critical"
    if score >= 0.80:
        return "high"
    if score >= 0.60:
        return "medium"
    return "low"


@app.post("/v1/predict")
def predict(req: PredictRequest) -> dict[str, Any]:
    batch = req.model_dump()
    contributors = contributor_errors(batch)

    if _session is None and _torch_model is None and _iforest is None:
        raise HTTPException(status_code=503, detail="A trained metrics model artifact is required")

    arr = window_to_tensor(batch, length=60)
    if _session is not None:
        raw_score = float(_session.run(None, {"window": arr[None, ...]})[0].reshape(-1)[0])
        version = "1.2.0"
    elif _torch_model is not None:
        import torch

        with torch.no_grad():
            x = torch.from_numpy(arr[None, ...])
            raw_score = float(_torch_model(x).item())
            # Prefer reconstruction residuals as contributors (before calibration)
            try:
                feat_resid = _torch_model.feature_residuals(x)[0].cpu().numpy()
                contributors = reconstruction_contributors(feat_resid) or contributors
            except Exception:  # noqa: BLE001
                pass
        version = "1.2.0-tranad"
    else:
        assert _iforest is not None
        raw_score = float(_iforest.score(arr))
        version = "1.2.0-iforest"

    calibrated = float(_calibrator.calibrate(raw_score))
    return {
        "risk_score": round(calibrated, 4),
        "raw_score": round(float(raw_score), 4),
        "calibrated_score": round(calibrated, 4),
        "severity": _severity(calibrated),
        "model_name": "metrics-model",
        "model_version": version,
        "contributors": contributors,
        "evidence": {
            "profile": req.profile,
            "missing_fraction": req.missing_fraction,
            "top_metrics": [c["metric"] for c in contributors],
        },
    }


def run() -> None:
    import uvicorn

    uvicorn.run("inference.app:app", host="0.0.0.0", port=8102, reload=False)


if __name__ == "__main__":
    run()
