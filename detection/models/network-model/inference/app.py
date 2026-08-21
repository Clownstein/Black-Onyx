from __future__ import annotations

from pathlib import Path
from typing import Any

from black_onyx_calibration import Calibrator, load_calibrator
from fastapi import FastAPI, HTTPException, Response, status
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

ARTIFACT_DIR = Path(__file__).resolve().parents[1] / "artifacts"
ONNX_PATH = ARTIFACT_DIR / "network_model.onnx"
PT_PATH = ARTIFACT_DIR / "network_model.pt"
CALIB_PATH = ARTIFACT_DIR / "calibration.json"

app = FastAPI(title="Network Model Inference", version="1.4.0")
_session = None
_torch_model: FlowTransformer | None = None
_calibrator: Calibrator = Calibrator()


def _load() -> None:
    global _session, _torch_model, _calibrator
    _calibrator = load_calibrator(CALIB_PATH)
    if ONNX_PATH.is_file() and ort is not None:
        try:
            _session = ort.InferenceSession(str(ONNX_PATH), providers=["CPUExecutionProvider"])
            # Reject ONNX if feature dim mismatch (legacy 16-dim artifacts)
            inp = _session.get_inputs()[0]
            shape = inp.shape
            if len(shape) >= 3 and isinstance(shape[2], int) and shape[2] != FEATURE_DIM:
                _session = None
            else:
                return
        except Exception:  # noqa: BLE001
            _session = None
    if PT_PATH.is_file():
        import torch

        _torch_model = FlowTransformer()
        try:
            state = torch.load(PT_PATH, map_location="cpu", weights_only=True)
            _torch_model.load_state_dict(state)
            _torch_model.eval()
        except Exception:  # noqa: BLE001 — legacy checkpoints
            _torch_model = None


@app.on_event("startup")
def startup() -> None:
    _load()


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
    if _session is not None:
        mode = "onnx"
    elif _torch_model is not None:
        mode = "torch"
    ready_now = mode in {"onnx", "torch"}
    if not ready_now:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return {"status": "ready" if ready_now else "not_ready", "mode": mode}


@app.post("/v1/predict")
def predict(req: PredictRequest) -> dict[str, Any]:
    batch = req.model_dump()
    if _session is None and _torch_model is None:
        raise HTTPException(status_code=503, detail="A trained network model artifact is required")

    feats, mask = flows_to_tensor(req.flows)
    contributors = feature_contributors(req.flows)

    if _session is not None:
        raw_score = float(_session.run(None, {"features": feats[None, ...]})[0].reshape(-1)[0])
        version = "1.4.0-onnx"
    else:
        import torch

        assert _torch_model is not None
        with torch.no_grad():
            x = torch.from_numpy(feats[None, ...])
            m = torch.from_numpy(mask[None, ...])
            score_t, attn = _torch_model.forward_with_attention(x, m)
            raw_score = float(score_t.item())
            contributors = attention_contributors(req.flows, attn[0].cpu().numpy()) or contributors
        version = "1.4.0-torch"

    calibrated = float(_calibrator.calibrate(raw_score))
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
