import json
from pathlib import Path
from types import SimpleNamespace

import numpy as np
import torch
from network_model.model import FEATURE_DIM, FlowTransformer, flows_to_tensor, heuristic_score
from training.train import load_dataset

EXAMPLE_DATASET = Path(__file__).resolve().parents[1] / "training" / "examples" / "platform_windows.jsonl"


def test_signed_package_onnx_name_loads(monkeypatch, tmp_path):
    from inference import app as inference

    model_path = tmp_path / "model.onnx"
    model_path.write_bytes(b"test fixture")
    (tmp_path / "config.json").write_text(json.dumps({"model_version": "1.0.1"}), encoding="utf-8")
    loaded = []

    class FakeSession:
        def __init__(self, path, providers):
            loaded.append(Path(path))

        def get_inputs(self):
            return [SimpleNamespace(shape=[1, 256, FEATURE_DIM])]

        def run(self, outputs, feed):
            return [np.array([0.5])]

    monkeypatch.setattr(inference, "ONNX_PATH", model_path)
    monkeypatch.setattr(inference, "LEGACY_ONNX_PATH", tmp_path / "network_model.onnx")
    monkeypatch.setattr(inference, "PT_PATH", tmp_path / "network_model.pt")
    monkeypatch.setattr(inference, "CALIB_PATH", tmp_path / "calibration.json")
    monkeypatch.setattr(inference, "CONFIG_PATH", tmp_path / "config.json")
    monkeypatch.setattr(inference, "ort", SimpleNamespace(InferenceSession=FakeSession))
    inference._load()
    assert loaded == [model_path]
    assert inference._session is not None
    assert inference._model_version == "1.0.1"
    assert inference.predict(inference.PredictRequest()).get("model_version") == "1.0.1"


def test_platform_dataset_uses_runtime_feature_layout():
    features, labels, mask = load_dataset(EXAMPLE_DATASET)
    assert features.shape == (8, 256, FEATURE_DIM)
    assert set(labels.tolist()) == {0.0, 1.0}
    assert mask.shape == (8, 256)
    assert bool(mask[0, 0]) is False


def test_forward_shape():
    model = FlowTransformer()
    x = torch.randn(2, 16, FEATURE_DIM)
    out = model(x)
    assert out.shape == (2,)
    assert torch.all((out >= 0) & (out <= 1))
    score, attn = model.forward_with_attention(x)
    assert score.shape == (2,)
    assert attn.shape == (2, 16)


def test_heuristic_and_tensor():
    flows = [
        {
            "src_port": 1234,
            "dst_port": 22,
            "protocol": "tcp",
            "bytes": 10,
            "packets": 1,
            "failed": True,
            "dst_is_external": True,
            "direction": "egress",
            "peer_hash": "abc",
            "ja3": "deadbeef",
            "ja4": "t13d",
            "sni": "rare-long-host-name-xyz.example.internal",
            "dns_qname": "aaaaaaaaaaaaaaaa.tunnel.example",
        }
    ]
    arr, mask = flows_to_tensor(flows, max_len=8)
    assert arr.shape == (8, FEATURE_DIM)
    assert mask[0] is False or mask[0] == False
    # JA3/JA4/SNI/DNS channels populated when present
    assert arr[0, 14] > 0.0 or arr[0, 15] > 0.0
    assert arr[0, 16] >= 0.0
    assert arr[0, 17] >= 0.0
    result = heuristic_score({"flows": flows, "detections": [{"score": 0.9}], "aggregates": {}})
    assert result["risk_score"] >= 0.9
    assert result.get("contributors")
