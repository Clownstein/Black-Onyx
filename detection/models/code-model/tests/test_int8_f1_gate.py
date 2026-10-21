"""Int8 ONNX quantization must not collapse DistilCodeEncoder ranking/F1."""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pytest
import torch

from code_model.encoder import DistilCodeEncoder, MAX_LEN, tokenize_diff


def _f1(y_true: np.ndarray, y_pred: np.ndarray) -> float:
    tp = int(((y_true == 1) & (y_pred == 1)).sum())
    fp = int(((y_true == 0) & (y_pred == 1)).sum())
    fn = int(((y_true == 1) & (y_pred == 0)).sum())
    if tp == 0:
        return 0.0
    precision = tp / (tp + fp)
    recall = tp / (tp + fn)
    return 2 * precision * recall / (precision + recall)


def _synthetic_batch() -> tuple[torch.Tensor, np.ndarray]:
    risky = [
        "+password = 'supersecret'\n+eval(user_input)\n",
        "+os.system(cmd)\n+api_key = 'AKIA'\n",
        "+subprocess.call(shell, shell=True)\n",
        "+pickle.loads(blob)\n+SECRET_TOKEN='x'\n",
        "+exec(code)\n+hardcoded_password='p'\n",
    ]
    safe = [
        "+def add(a, b):\n+    return a + b\n",
        "+x = 1\n+y = x + 2\n",
        "+print('hello')\n",
        "+class Point:\n+    pass\n",
        "+from typing import List\n",
    ]
    texts = risky + safe
    labels = np.asarray([1] * len(risky) + [0] * len(safe), dtype=np.int64)
    ids = np.stack([tokenize_diff(t) for t in texts], axis=0)
    return torch.tensor(ids, dtype=torch.long), labels


def test_int8_quantization_f1_regression(tmp_path: Path) -> None:
    pytest.importorskip("onnxruntime")
    from onnxruntime import InferenceSession
    from onnxruntime.quantization import QuantType, quantize_dynamic

    enc = DistilCodeEncoder()
    enc.eval()
    # Light supervised nudge so scores separate risky vs safe on this fixture.
    opt = torch.optim.Adam(enc.parameters(), lr=1e-3)
    batch, labels = _synthetic_batch()
    target = torch.tensor(labels, dtype=torch.float32)
    for _ in range(60):
        opt.zero_grad()
        out = enc(batch)
        loss = torch.nn.functional.binary_cross_entropy(out, target)
        loss.backward()
        opt.step()

    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    pt_path = artifacts / "distil_encoder.pt"
    torch.save(enc.state_dict(), pt_path)

    onnx_path = artifacts / "model.onnx"
    dummy = torch.zeros(1, MAX_LEN, dtype=torch.long)
    torch.onnx.export(
        enc,
        dummy,
        str(onnx_path),
        input_names=["input_ids"],
        output_names=["score"],
        dynamic_axes={"input_ids": {0: "batch"}, "score": {0: "batch"}},
        opset_version=17,
        dynamo=False,
    )
    int8_path = artifacts / "model.int8.onnx"
    quantize_dynamic(
        model_input=str(onnx_path),
        model_output=str(int8_path),
        weight_type=QuantType.QInt8,
    )

    float_sess = InferenceSession(str(onnx_path), providers=["CPUExecutionProvider"])
    int8_sess = InferenceSession(str(int8_path), providers=["CPUExecutionProvider"])
    feeds = {"input_ids": batch.numpy()}
    float_scores = np.asarray(float_sess.run(None, feeds)[0]).reshape(-1)
    int8_scores = np.asarray(int8_sess.run(None, feeds)[0]).reshape(-1)

    # Normalize to probabilities if logits.
    def _as_prob(scores: np.ndarray) -> np.ndarray:
        if scores.min() >= 0.0 and scores.max() <= 1.0:
            return scores
        return 1.0 / (1.0 + np.exp(-scores))

    float_prob = _as_prob(float_scores)
    int8_prob = _as_prob(int8_scores)
    float_pred = (float_prob >= 0.5).astype(np.int64)
    int8_pred = (int8_prob >= 0.5).astype(np.int64)

    float_f1 = _f1(labels, float_pred)
    int8_f1 = _f1(labels, int8_pred)
    # Gate: int8 must stay within 0.15 F1 of float on this synthetic holdout.
    assert float_f1 >= 0.5, f"float baseline too weak for gate: F1={float_f1}"
    assert int8_f1 + 1e-9 >= float_f1 - 0.15, (
        f"int8 F1 regression too large: float={float_f1:.3f} int8={int8_f1:.3f}"
    )
