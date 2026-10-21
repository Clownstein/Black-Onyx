from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import joblib
from black_onyx_calibration import Calibrator, load_calibrator
from fastapi import FastAPI, HTTPException, Query, Response, status
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

ARTIFACT_DIR = Path(os.environ.get("METRICS_MODEL_ARTIFACTS_DIR", Path(__file__).resolve().parents[1] / "artifacts"))
ONNX_PATH = ARTIFACT_DIR / "model.onnx"
LEGACY_ONNX_PATH = ARTIFACT_DIR / "metrics_model.onnx"
PT_PATH = ARTIFACT_DIR / "metrics_model.pt"
IFOREST_PATH = ARTIFACT_DIR / "isolation_forest.joblib"
CALIB_PATH = ARTIFACT_DIR / "calibration.json"
CONFIG_PATH = ARTIFACT_DIR / "config.json"

app = FastAPI(title="Metrics Model Inference", version="1.2.0")
_session = None
_torch_model: MultivariateMetricTransformer | None = None
_iforest: IsolationForestFallback | None = None
_calibrator: Calibrator = Calibrator()
_model_version: str | None = None


def _load() -> None:
    global _session, _torch_model, _iforest, _calibrator, _model_version
    runtime = _load_from(CONFIG_PATH, CALIB_PATH, IFOREST_PATH, (ONNX_PATH, LEGACY_ONNX_PATH), PT_PATH)
    _session = runtime["session"]
    _torch_model = runtime["torch_model"]
    _iforest = runtime["iforest"]
    _calibrator = runtime["calibrator"]
    _model_version = runtime["model_version"]


def _load_from(
    config_path: Path, calib_path: Path, iforest_path: Path,
    onnx_candidates: tuple[Path, ...], pt_path: Path,
) -> dict[str, Any]:
    runtime: dict[str, Any] = {
        "session": None, "torch_model": None, "iforest": None, "model_version": None,
    }
    if config_path.is_file():
        config = json.loads(config_path.read_text(encoding="utf-8"))
        version = config.get("model_version") if isinstance(config, dict) else None
        if not isinstance(version, str) or not version.strip():
            raise ValueError("Metrics model config has no model_version")
        runtime["model_version"] = version
    runtime["calibrator"] = load_calibrator(calib_path)
    if iforest_path.is_file():
        runtime["iforest"] = joblib.load(iforest_path)
    onnx_path = next((path for path in onnx_candidates if path.is_file()), None)
    if onnx_path is not None and ort is not None:
        runtime["session"] = ort.InferenceSession(str(onnx_path), providers=["CPUExecutionProvider"])
        return runtime
    if pt_path.is_file():
        import torch

        torch_model = MultivariateMetricTransformer()
        state = torch.load(pt_path, map_location="cpu", weights_only=True)
        try:
            torch_model.load_state_dict(state)
            torch_model.eval()
            runtime["torch_model"] = torch_model
        except Exception:  # noqa: BLE001 older classifier-only checkpoints
            pass
    return runtime


def _load_package(package_dir: Path) -> dict[str, Any]:
    """Loader for orchestrator-managed signed packages (already verified)."""
    runtime = _load_from(
        package_dir / "config.json", package_dir / "calibration.json",
        package_dir / "isolation_forest.joblib", (package_dir / "model.onnx",),
        package_dir / "metrics_model.pt",
    )
    if runtime["session"] is None and runtime["torch_model"] is None and runtime["iforest"] is None:
        raise ValueError("Signed metrics package has no loadable weights")
    return runtime


def _configure_serving():
    from black_onyx_model_package.serving import configure_from_env

    return configure_from_env("metrics-model", _load_package)


serving_registry, serving_sync = _configure_serving()


@app.on_event("startup")
def startup() -> None:
    _load()
    if serving_sync is not None:
        serving_sync.start()


def _runtime(alias: str | None) -> dict[str, Any]:
    """Signed package serving ``alias``; the baked artifact is dev-only."""
    if serving_registry is not None:
        slot = serving_registry.get(alias)
        if slot is None:
            raise HTTPException(status_code=503, detail="No signed metrics model package is loaded yet")
        return slot.model
    return {
        "session": _session, "torch_model": _torch_model, "iforest": _iforest,
        "calibrator": _calibrator, "model_version": _model_version,
    }


@app.get("/v1/serving")
def serving_status() -> dict[str, Any]:
    if serving_registry is None:
        return {"enabled": False, "baked_version": _model_version}
    return {"enabled": True, **serving_registry.status()}


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
    try:
        runtime = _runtime("champion")
    except HTTPException:
        runtime = {"session": None, "torch_model": None, "iforest": None}
    if runtime["session"] is not None:
        mode = "onnx"
    elif runtime["torch_model"] is not None:
        mode = "torch"
    elif runtime["iforest"] is not None:
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
def predict(req: PredictRequest, alias: str | None = Query(default=None)) -> dict[str, Any]:
    runtime = _runtime(alias if isinstance(alias, str) else None)
    session, torch_model, iforest = runtime["session"], runtime["torch_model"], runtime["iforest"]
    model_version = runtime["model_version"]
    batch = req.model_dump()
    contributors = contributor_errors(batch)

    if session is None and torch_model is None and iforest is None:
        raise HTTPException(status_code=503, detail="A trained metrics model artifact is required")

    arr = window_to_tensor(batch, length=60)
    if session is not None:
        raw_score = float(session.run(None, {"window": arr[None, ...]})[0].reshape(-1)[0])
        version = model_version or "1.2.0"
    elif torch_model is not None:
        import torch

        with torch.no_grad():
            x = torch.from_numpy(arr[None, ...])
            raw_score = float(torch_model(x).item())
            # Prefer reconstruction residuals as contributors (before calibration)
            try:
                feat_resid = torch_model.feature_residuals(x)[0].cpu().numpy()
                contributors = reconstruction_contributors(feat_resid) or contributors
            except Exception:  # noqa: BLE001
                pass
        version = model_version or "1.2.0-tranad"
    else:
        assert iforest is not None
        raw_score = float(iforest.score(arr))
        version = model_version or "1.2.0-iforest"

    calibrated = float(runtime["calibrator"].calibrate(raw_score))
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
