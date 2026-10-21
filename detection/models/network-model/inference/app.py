from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from black_onyx_calibration import Calibrator, load_calibrator
from fastapi import FastAPI, HTTPException, Query, Response, status
from pydantic import BaseModel

from network_model.model import (
    FEATURE_DIM,
    FlowTransformer,
    attention_contributors,
    feature_contributors,
    flows_to_tensor,
)

try:
    import onnxruntime as ort
except ImportError:  # pragma: no cover
    ort = None

ARTIFACT_DIR = Path(os.environ.get("NETWORK_MODEL_ARTIFACTS_DIR", Path(__file__).resolve().parents[1] / "artifacts"))
ONNX_PATH = ARTIFACT_DIR / "model.onnx"
LEGACY_ONNX_PATH = ARTIFACT_DIR / "network_model.onnx"
PT_PATH = ARTIFACT_DIR / "network_model.pt"
CALIB_PATH = ARTIFACT_DIR / "calibration.json"
CONFIG_PATH = ARTIFACT_DIR / "config.json"

app = FastAPI(title="Network Model Inference", version="1.4.0")
_session = None
_torch_model: FlowTransformer | None = None
_calibrator: Calibrator = Calibrator()
_model_version: str | None = None


def _load() -> None:
    global _session, _torch_model, _calibrator, _model_version
    runtime = _load_from(CONFIG_PATH, CALIB_PATH, (ONNX_PATH, LEGACY_ONNX_PATH), PT_PATH)
    _session = runtime["session"]
    _torch_model = runtime["torch_model"]
    _calibrator = runtime["calibrator"]
    _model_version = runtime["model_version"]


def _load_package(package_dir: Path) -> dict[str, Any]:
    """Loader for orchestrator-managed signed packages (already verified)."""
    runtime = _load_from(
        package_dir / "config.json", package_dir / "calibration.json",
        (package_dir / "model.onnx",), package_dir / "network_model.pt",
    )
    if runtime["session"] is None and runtime["torch_model"] is None:
        raise ValueError("Signed network package has no loadable weights")
    return runtime


def _load_from(
    config_path: Path, calib_path: Path, onnx_candidates: tuple[Path, ...], pt_path: Path,
) -> dict[str, Any]:
    session = None
    torch_model = None
    model_version = None
    if config_path.is_file():
        config = json.loads(config_path.read_text(encoding="utf-8"))
        version = config.get("model_version") if isinstance(config, dict) else None
        if not isinstance(version, str) or not version.strip():
            raise ValueError("Network model config has no model_version")
        model_version = version
    calibrator = load_calibrator(calib_path)
    runtime: dict[str, Any] = {
        "session": None, "torch_model": None, "calibrator": calibrator, "model_version": model_version,
    }
    onnx_path = next((path for path in onnx_candidates if path.is_file()), None)
    if onnx_path is not None and ort is not None:
        try:
            session = ort.InferenceSession(str(onnx_path), providers=["CPUExecutionProvider"])
            # Reject ONNX if feature dim mismatch (legacy 16-dim artifacts)
            shape = session.get_inputs()[0].shape
            if not (len(shape) >= 3 and isinstance(shape[2], int) and shape[2] != FEATURE_DIM):
                runtime["session"] = session
                return runtime
        except Exception:  # noqa: BLE001
            pass
    if pt_path.is_file():
        import torch

        torch_model = FlowTransformer()
        try:
            state = torch.load(pt_path, map_location="cpu", weights_only=True)
            torch_model.load_state_dict(state)
            torch_model.eval()
            runtime["torch_model"] = torch_model
        except Exception:  # noqa: BLE001 legacy checkpoints
            pass
    return runtime


def _configure_serving():
    from black_onyx_model_package.serving import configure_from_env

    return configure_from_env("network-model", _load_package)


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
            raise HTTPException(status_code=503, detail="No signed network model package is loaded yet")
        return slot.model
    return {
        "session": _session, "torch_model": _torch_model,
        "calibrator": _calibrator, "model_version": _model_version,
    }


@app.get("/v1/serving")
def serving_status() -> dict[str, Any]:
    if serving_registry is None:
        return {"enabled": False, "baked_version": _model_version}
    return {"enabled": True, **serving_registry.status()}


class PredictRequest(BaseModel):
    flows: list[dict[str, Any]] = []
    detections: list[dict[str, Any]] = []
    aggregates: dict[str, Any] = {}


@app.get("/health/live")
def live() -> dict[str, str]:
    return {"status": "alive"}


@app.get("/health/ready")
def ready(response: Response) -> dict[str, object]:
    mode = "heuristic"
    try:
        runtime = _runtime("champion")
    except HTTPException:
        runtime = {"session": None, "torch_model": None}
    if runtime["session"] is not None:
        mode = "onnx"
    elif runtime["torch_model"] is not None:
        mode = "torch"
    ready_now = mode in {"onnx", "torch"}
    if not ready_now:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return {"status": "ready" if ready_now else "not_ready", "mode": mode}


@app.post("/v1/predict")
def predict(req: PredictRequest, alias: str | None = Query(default=None)) -> dict[str, Any]:
    runtime = _runtime(alias if isinstance(alias, str) else None)
    session, torch_model = runtime["session"], runtime["torch_model"]
    model_version = runtime["model_version"]
    if session is None and torch_model is None:
        raise HTTPException(status_code=503, detail="A trained network model artifact is required")

    feats, mask = flows_to_tensor(req.flows)
    contributors = feature_contributors(req.flows)

    if session is not None:
        raw_score = float(session.run(None, {"features": feats[None, ...]})[0].reshape(-1)[0])
        version = model_version or "1.4.0-onnx"
    else:
        import torch

        assert torch_model is not None
        with torch.no_grad():
            x = torch.from_numpy(feats[None, ...])
            m = torch.from_numpy(mask[None, ...])
            score_t, attn = torch_model.forward_with_attention(x, m)
            raw_score = float(score_t.item())
            contributors = attention_contributors(req.flows, attn[0].cpu().numpy()) or contributors
        version = model_version or "1.4.0-torch"

    calibrated = float(runtime["calibrator"].calibrate(raw_score))
    return {
        "risk_score": round(calibrated, 4),
        "raw_score": round(float(raw_score), 4),
        "calibrated_score": round(calibrated, 4),
        "severity": _severity(calibrated),
        "model_name": "network-model",
        "model_version": version,
        "contributors": contributors,
        "evidence": {
            "detections": req.detections,
            "aggregates": req.aggregates,
            "top_contributors": contributors,
        },
    }


def _severity(score: float) -> str:
    if score >= 0.95:
        return "critical"
    if score >= 0.86:
        return "high"
    if score >= 0.72:
        return "medium"
    return "low"


def run() -> None:
    import uvicorn

    uvicorn.run("inference.app:app", host="0.0.0.0", port=8101, reload=False)


if __name__ == "__main__":
    run()
