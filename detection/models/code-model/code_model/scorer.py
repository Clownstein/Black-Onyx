from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from black_onyx_calibration import Calibrator, fit_platt, load_calibrator, save_calibrator
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from code_model.features import (
    FEATURE_NAMES,
    build_evidence,
    extract_feature_flags,
    feature_vector,
    risk_categories,
)

try:
    import onnxruntime as ort
except ImportError:  # pragma: no cover
    ort = None


class ChangeRiskModel:
    """Hybrid DistilBERT-style encoder + sklearn logistic risk scorer.

    Inference order: ONNX encoder → torch DistilCodeEncoder → sklearn → heuristic.
    Semgrep/heuristic evidence always attached. Advisory-only.
    """

    def __init__(self) -> None:
        self.model: Pipeline | None = None
        self.model_version = "2.1.0"
        self.feature_names = list(FEATURE_NAMES)
        self.thresholds = {"medium": 0.55, "high": 0.75, "critical": 0.9}
        self.policy = {"advisory_only": True, "allow_model_only_blocking": False}
        self.calibrator: Calibrator = Calibrator()
        self.backend = "heuristic"
        self._session = None
        self._torch_encoder = None
        self._artifacts_dir: Path | None = None

    def fit(self, samples: list[dict[str, Any]], labels: list[int]) -> None:
        x = np.vstack([feature_vector(s) for s in samples])
        y = np.asarray(labels, dtype=int)
        self.model = Pipeline(
            [
                ("scaler", StandardScaler()),
                ("clf", LogisticRegression(max_iter=1000, random_state=42)),
            ]
        )
        self.model.fit(x, y)
        # Fit Platt on sklearn raw probabilities for calibrated_score path
        proba = self.model.predict_proba(x)[:, 1]
        self.calibrator = Calibrator(fit_platt(proba.tolist(), labels))
        self.backend = "sklearn"

        # Train DistilBERT-style encoder for ONNX export; scoring stays sklearn until load().
        try:
            self._fit_encoder(samples, labels)
        except Exception:  # noqa: BLE001
            self._torch_encoder = None

    def _fit_encoder(self, samples: list[dict[str, Any]], labels: list[int]) -> None:
        import torch
        from torch import nn

        from code_model.encoder import DistilCodeEncoder, encode_batch

        texts = [str(s.get("diff_text") or (s.get("text_features") or {}).get("diff_text") or "") for s in samples]
        ids = torch.from_numpy(encode_batch(texts))
        y = torch.tensor(labels, dtype=torch.float32)
        enc = DistilCodeEncoder()
        opt = torch.optim.AdamW(enc.parameters(), lr=1e-3)
        loss_fn = nn.BCELoss()
        enc.train()
        for _ in range(8):
            opt.zero_grad()
            pred = enc(ids)
            loss = loss_fn(pred, y)
            loss.backward()
            opt.step()
        enc.eval()
        self._torch_encoder = enc
        # Keep sklearn backend/calibrator for in-memory predict; encoder used after load.

    def save(self, artifacts_dir: Path) -> None:
        artifacts_dir.mkdir(parents=True, exist_ok=True)
        joblib.dump(
            {
                "model": self.model,
                "version": self.model_version,
                "feature_names": self.feature_names,
            },
            artifacts_dir / "model.joblib",
        )
        save_calibrator(self.calibrator.artifact, artifacts_dir / "calibration.json")
        (artifacts_dir / "config.json").write_text(
            json.dumps(
                {
                    "model_name": "code-model",
                    "model_version": self.model_version,
                    "feature_names": self.feature_names,
                    "policy": self.policy,
                    "encoder": "distilbert-style" if self._torch_encoder is not None else "sklearn",
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        (artifacts_dir / "thresholds.json").write_text(
            json.dumps(self.thresholds, indent=2) + "\n",
            encoding="utf-8",
        )
        if self._torch_encoder is not None:
            import torch

            pt_path = artifacts_dir / "distil_encoder.pt"
            torch.save(self._torch_encoder.state_dict(), pt_path)
            # Prefer ONNX export for inference
            try:
                from code_model.encoder import MAX_LEN

                dummy = torch.zeros(1, MAX_LEN, dtype=torch.long)
                onnx_path = artifacts_dir / "model.onnx"
                torch.onnx.export(
                    self._torch_encoder,
                    dummy,
                    str(onnx_path),
                    input_names=["input_ids"],
                    output_names=["score"],
                    dynamic_axes={"input_ids": {0: "batch"}, "score": {0: "batch"}},
                    opset_version=17,
                    dynamo=False,
                )
            except Exception:  # noqa: BLE001
                onnx_path.unlink(missing_ok=True)

    def load(self, artifacts_dir: Path) -> None:
        self._artifacts_dir = artifacts_dir
        blob = joblib.load(artifacts_dir / "model.joblib")
        self.model = blob["model"]
        self.model_version = blob.get("version", self.model_version)
        self.feature_names = blob.get("feature_names", self.feature_names)
        self.calibrator = load_calibrator(artifacts_dir / "calibration.json")
        cfg_path = artifacts_dir / "config.json"
        if cfg_path.is_file():
            cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
            self.model_version = str(cfg.get("model_version", self.model_version))
            self.policy = cfg.get("policy") or self.policy
        thr_path = artifacts_dir / "thresholds.json"
        if thr_path.is_file():
            self.thresholds = json.loads(thr_path.read_text(encoding="utf-8"))

        onnx_path = artifacts_dir / "model.onnx"
        pt_path = artifacts_dir / "distil_encoder.pt"
        if onnx_path.is_file() and ort is not None:
            try:
                self._session = ort.InferenceSession(str(onnx_path), providers=["CPUExecutionProvider"])
                self.backend = "onnx"
                return
            except Exception:  # noqa: BLE001
                self._session = None
        if pt_path.is_file():
            try:
                import torch

                from code_model.encoder import DistilCodeEncoder

                enc = DistilCodeEncoder()
                enc.load_state_dict(torch.load(pt_path, map_location="cpu", weights_only=True))
                enc.eval()
                self._torch_encoder = enc
                self.backend = "distil-encoder"
                return
            except Exception:  # noqa: BLE001
                self._torch_encoder = None
        self.backend = "sklearn" if self.model is not None else "heuristic"

    def _encoder_score(self, payload: dict[str, Any]) -> float | None:
        text = str(
            payload.get("diff_text")
            or (payload.get("text_features") or {}).get("diff_text")
            or payload.get("diff")
            or ""
        )
        from code_model.encoder import encode_batch

        ids = encode_batch([text])
        if self._session is not None:
            score = float(self._session.run(None, {"input_ids": ids})[0].reshape(-1)[0])
            return score
        if self._torch_encoder is not None:
            import torch

            with torch.no_grad():
                return float(self._torch_encoder(torch.from_numpy(ids)).item())
        return None

    def predict(self, payload: dict[str, Any]) -> dict[str, Any]:
        flags = extract_feature_flags(payload)
        vector = feature_vector(payload).reshape(1, -1)
        # Contributors / evidence from Semgrep + heuristics BEFORE calibration
        evidence = build_evidence(payload)
        contributors = [
            {
                "file": e.get("file"),
                "start_line": e.get("start_line"),
                "end_line": e.get("end_line"),
                "summary": e.get("summary"),
                "type": "scanner_or_heuristic",
            }
            for e in evidence
        ]

        enc_score = None
        if self.backend in {"onnx", "distil-encoder"}:
            enc_score = self._encoder_score(payload)
        if enc_score is not None:
            raw_score = float(enc_score)
            backend = self.backend
        elif self.model is None:
            raw_score = float(
                min(
                    0.99,
                    0.12
                    + 0.25 * flags["has_shell_true"]
                    + 0.25 * flags["has_eval"]
                    + 0.2 * flags["secret_like"]
                    + 0.08 * flags["semgrep_high"]
                    + 0.1 * flags["auth_path"]
                    + 0.03 * flags["change_size_log"],
                )
            )
            backend = "heuristic"
        else:
            proba = self.model.predict_proba(vector)[0]
            raw_score = float(proba[1] if len(proba) > 1 else proba[0])
            backend = "sklearn"

        calibrated = float(self.calibrator.calibrate(raw_score))
        return {
            "risk_score": round(calibrated, 4),
            "raw_score": round(raw_score, 4),
            "calibrated_score": round(calibrated, 4),
            "risk_categories": risk_categories(flags),
            "evidence": evidence,
            "contributors": contributors,
            "model_version": self.model_version,
            "model_name": "code-model",
            "meta": {"advisory_only": True, "policy": self.policy, "backend": backend},
            "advisory_only": True,
            "features": flags,
        }
