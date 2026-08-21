"""Scoring backends with an offline heuristic available for unit diagnostics.

LogBERT-style: MLM (masked template prediction) + sequence corruption head.
Contributors are derived from attention/mismatch on the raw score path, then
`black_onyx_calibration` maps raw → calibrated probability.
"""

from __future__ import annotations

import json
import math
import sys
from pathlib import Path
from typing import Any

import numpy as np
from black_onyx_calibration import Calibrator, load_calibrator

from log_model.vocab import TemplateVocab, severity_id

# Allow importing models/common AnomalyModel protocol when running from repo.
_COMMON = Path(__file__).resolve().parents[2] / "common"
if str(_COMMON.parent) not in sys.path:
    sys.path.insert(0, str(_COMMON.parent))

try:
    from common.anomaly_model import AnomalyModel  # type: ignore
except Exception:  # noqa: BLE001
    AnomalyModel = object  # type: ignore


def _sigmoid(x: float) -> float:
    return 1.0 / (1.0 + math.exp(-x))


class LogAnomalyScorer:
    """Implements the AnomalyModel protocol for log sequences (LogBERT-style)."""

    model_name = "log-transformer"
    model_version = "0.1.0"
    feature_version = "1.0"

    def __init__(self, artifacts_dir: Path | None = None) -> None:
        self.artifacts_dir = artifacts_dir or Path(__file__).resolve().parents[1] / "artifacts"
        self.backend = "heuristic"
        self.vocab = TemplateVocab()
        self.config: dict[str, Any] = {}
        self.calibrator: Calibrator = Calibrator()
        self.thresholds: dict[str, float] = {"medium": 0.6, "high": 0.8, "critical": 0.93}
        self._session = None
        self._torch_model = None
        self._torch = None
        self.load_error: str | None = None
        self._load()

    def _load(self) -> None:
        vocab_path = self.artifacts_dir / "vocab.json"
        config_path = self.artifacts_dir / "config.json"
        calib_path = self.artifacts_dir / "calibration.json"
        thresh_path = self.artifacts_dir / "thresholds.json"
        if vocab_path.is_file():
            self.vocab = TemplateVocab.load(vocab_path)
        if config_path.is_file():
            self.config = json.loads(config_path.read_text(encoding="utf-8"))
            self.model_version = str(self.config.get("model_version", self.model_version))
            self.feature_version = str(self.config.get("feature_version", self.feature_version))
        self.calibrator = load_calibrator(calib_path)
        if thresh_path.is_file():
            self.thresholds = json.loads(thresh_path.read_text(encoding="utf-8"))

        onnx_path = self.artifacts_dir / "model.onnx"
        ckpt_path = self.artifacts_dir / "model.pt"
        if onnx_path.is_file():
            try:
                import onnxruntime as ort

                self._session = ort.InferenceSession(
                    str(onnx_path), providers=["CPUExecutionProvider"]
                )
                self.backend = "onnx"
                return
            except Exception as exc:  # noqa: BLE001
                self._session = None
                self.load_error = f"ONNX load failed: {exc}"

        if ckpt_path.is_file():
            try:
                import torch

                from log_model.model import LogTransformer, LogTransformerConfig

                self._torch = torch
                cfg = LogTransformerConfig.from_dict(self.config.get("model", {}))
                if "vocab_size" not in self.config.get("model", {}):
                    cfg.vocab_size = len(self.vocab.token_to_id)
                model = LogTransformer(cfg)
                state = torch.load(ckpt_path, map_location="cpu", weights_only=True)
                model.load_state_dict(state)
                model.eval()
                self._torch_model = model
                self.backend = "pytorch"
                return
            except Exception as exc:  # noqa: BLE001
                self._torch_model = None
                self.load_error = f"PyTorch load failed: {exc}"

        self.backend = "heuristic"

    def health(self) -> dict[str, Any]:
        return {
            "status": "ready" if self.backend in {"onnx", "pytorch"} else "not_ready",
            "backend": self.backend,
            "model_name": self.model_name,
            "model_version": self.model_version,
            "feature_version": self.feature_version,
            "artifacts_dir": str(self.artifacts_dir),
            "error": self.load_error,
        }

    def validate_input(self, batch: dict[str, Any]) -> None:
        if "items" not in batch or not isinstance(batch["items"], list):
            raise ValueError("batch.items must be a list")
        if not batch["items"]:
            raise ValueError("batch.items must not be empty")
        for item in batch["items"]:
            events = item.get("events") or item.get("sequence") or []
            if not events:
                raise ValueError("each item requires events/sequence")

    def predict(self, batch: dict[str, Any]) -> dict[str, Any]:
        self.validate_input(batch)
        results = []
        for item in batch["items"]:
            results.append(self._score_item(item))
        return {
            "request_id": batch.get("request_id"),
            "tenant_id": batch.get("tenant_id"),
            "model_name": self.model_name,
            "model_version": self.model_version,
            "feature_version": batch.get("feature_version") or self.feature_version,
            "results": results,
        }

    def _score_item(self, item: dict[str, Any]) -> dict[str, Any]:
        events = item.get("events") or item.get("sequence") or []
        input_ids, severity_ids, attention_mask, template_ids = self._encode(events)

        if self.backend == "onnx" and self._session is not None:
            outputs = self._session.run(
                None,
                {
                    "input_ids": input_ids.astype(np.int64),
                    "severity_ids": severity_ids.astype(np.int64),
                    "attention_mask": attention_mask.astype(np.int64),
                },
            )
            token_logits = outputs[0][0]
            corruption_logit = float(outputs[1][0])
            raw_score, contributors = self._scores_from_logits(
                token_logits, corruption_logit, input_ids[0], attention_mask[0], template_ids
            )
        elif self.backend == "pytorch" and self._torch_model is not None and self._torch is not None:
            torch = self._torch
            with torch.no_grad():
                out = self._torch_model(
                    torch.tensor(input_ids, dtype=torch.long),
                    torch.tensor(severity_ids, dtype=torch.long),
                    torch.tensor(attention_mask, dtype=torch.long),
                )
            token_logits = out["token_logits"][0].cpu().numpy()
            corruption_logit = float(out["corruption_logit"][0].cpu().numpy())
            attn = None
            if "attention_weights" in out:
                attn = out["attention_weights"][0].cpu().numpy()
            raw_score, contributors = self._scores_from_logits(
                token_logits,
                corruption_logit,
                input_ids[0],
                attention_mask[0],
                template_ids,
                attention_weights=attn,
            )
        else:
            raw_score, contributors = self._heuristic_score(template_ids, events)

        # Contributors are populated from attention/mismatch *before* calibration.
        calibrated = self.calibrator.calibrate(float(raw_score))
        return {
            "sequence_id": item.get("sequence_id"),
            "raw_score": float(raw_score),
            "calibrated_score": float(calibrated),
            "top_contributors": contributors[:5],
            "model_version": self.model_version,
            "backend": self.backend,
        }

    def _encode(
        self, events: list[dict[str, Any]]
    ) -> tuple[np.ndarray, np.ndarray, np.ndarray, list[str]]:
        max_len = int(self.config.get("model", {}).get("max_position_embeddings", 128))
        ids: list[int] = []
        sev: list[int] = []
        templates: list[str] = []
        for event in events[:max_len]:
            template_id = str(event.get("template_id") or "[UNK]")
            templates.append(template_id)
            ids.append(self.vocab.encode(template_id))
            sev.append(severity_id(event.get("severity")))
        pad_len = max_len - len(ids)
        attention = [1] * len(ids) + [0] * pad_len
        ids = ids + [self.vocab.pad_id] * pad_len
        sev = sev + [0] * pad_len
        return (
            np.array([ids], dtype=np.int64),
            np.array([sev], dtype=np.int64),
            np.array([attention], dtype=np.int64),
            templates,
        )

    def _scores_from_logits(
        self,
        token_logits: np.ndarray,
        corruption_logit: float,
        input_ids: np.ndarray,
        attention_mask: np.ndarray,
        template_ids: list[str],
        attention_weights: np.ndarray | None = None,
    ) -> tuple[float, list[dict[str, Any]]]:
        contributors: list[dict[str, Any]] = []
        nlls: list[float] = []
        for pos, template_id in enumerate(template_ids):
            if attention_mask[pos] == 0:
                continue
            logits = token_logits[pos]
            # log-softmax NLL for observed token (LogBERT masked-key mismatch)
            exp = np.exp(logits - logits.max())
            probs = exp / exp.sum()
            token_id = int(input_ids[pos])
            prob = float(probs[token_id]) if token_id < len(probs) else 1e-9
            nll = -math.log(max(prob, 1e-9))
            nlls.append(nll)
            attn_mass = float(attention_weights[pos]) if attention_weights is not None else 0.0
            contribution = float(nll) + 0.5 * attn_mass
            top_ids = np.argsort(logits)[-3:][::-1]
            contributors.append(
                {
                    "position": pos,
                    "observed_template": template_id,
                    "expected_templates": [self.vocab.decode(int(i)) for i in top_ids],
                    "contribution": contribution,
                    "attention_weight": attn_mass,
                    "type": "unexpected_template",
                }
            )
        contributors.sort(key=lambda c: c["contribution"], reverse=True)
        masked_loss = float(np.mean(nlls)) if nlls else 0.0
        corruption_prob = _sigmoid(corruption_logit)
        novelty = sum(1 for t in template_ids if t not in self.vocab.token_to_id) / max(
            len(template_ids), 1
        )
        raw = 0.45 * masked_loss + 0.20 * corruption_prob + 0.15 * novelty
        return raw, contributors

    def _heuristic_score(
        self, template_ids: list[str], events: list[dict[str, Any]]
    ) -> tuple[float, list[dict[str, Any]]]:
        """Deterministic scorer for CI when no trained artifacts exist."""
        benign = {
            "tpl-auth-success",
            "tpl-auth-failure",
            "tpl-session-create",
            "tpl-session-refresh",
            "tpl-db-query",
            "tpl-cache-hit",
            "tpl-http-200",
            "tpl-http-401",
            "tpl-health-ok",
            "tpl-config-reload",
        }
        # Expected auth-service transitions (underspecified pairs are mildly surprising).
        expected_next: dict[str, set[str]] = {
            "tpl-auth-success": {"tpl-session-create", "tpl-auth-failure", "tpl-auth-success"},
            "tpl-session-create": {"tpl-auth-failure", "tpl-session-refresh", "tpl-db-query"},
            "tpl-auth-failure": {"tpl-session-refresh", "tpl-auth-success", "tpl-http-401"},
            "tpl-session-refresh": {"tpl-db-query", "tpl-cache-hit", "tpl-http-200"},
            "tpl-db-query": {"tpl-http-200", "tpl-cache-hit", "tpl-db-query"},
            "tpl-http-200": {"tpl-cache-hit", "tpl-auth-success", "tpl-db-query"},
            "tpl-cache-hit": {"tpl-auth-success", "tpl-http-200", "tpl-db-query"},
        }
        suspicious_tokens = ("privilege", "shell", "novel", "external", "unknown")

        contributors: list[dict[str, Any]] = []
        counts: dict[str, int] = {}
        for t in template_ids:
            counts[t] = counts.get(t, 0) + 1

        transition_pen = 0.0
        for a, b in zip(template_ids, template_ids[1:], strict=False):
            allowed = expected_next.get(a)
            if allowed is not None and b not in allowed:
                transition_pen += 0.45

        for pos, template_id in enumerate(template_ids):
            rarity = 1.0 / counts[template_id]
            suspicious = any(tok in template_id.lower() for tok in suspicious_tokens)
            privilege_boost = 1.6 if suspicious else 0.0
            novel_boost = 0.0
            if template_id not in benign and template_id not in self.vocab.token_to_id:
                novel_boost = 1.2
            elif template_id not in benign:
                novel_boost = 0.9
            severity = str(events[pos].get("severity") or "INFO").upper()
            sev_boost = 0.5 if severity in {"ERROR", "CRITICAL", "ALERT"} else 0.0
            contribution = rarity + privilege_boost + novel_boost + sev_boost
            contributors.append(
                {
                    "position": pos,
                    "observed_template": template_id,
                    "expected_templates": ["tpl-auth-success", "tpl-auth-failure"],
                    "contribution": float(contribution),
                    "type": "unexpected_template",
                }
            )
        contributors.sort(key=lambda c: c["contribution"], reverse=True)
        max_c = contributors[0]["contribution"] if contributors else 0.0
        # Length anomalies (deletion/insertion) relative to common window size 8.
        length_pen = abs(len(template_ids) - 8) * 0.25
        raw = 0.45 * max_c + 0.35 * transition_pen + length_pen
        return float(raw), contributors


# Runtime check against protocol when available
def _assert_protocol() -> None:
    scorer = LogAnomalyScorer(artifacts_dir=Path("/nonexistent"))
    if hasattr(AnomalyModel, "__protocol_attrs__") or callable(getattr(AnomalyModel, "__instancecheck__", None)):
        assert isinstance(scorer, AnomalyModel) or AnomalyModel is object
