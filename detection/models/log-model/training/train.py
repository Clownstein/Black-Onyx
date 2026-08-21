"""Train a LogBERT-style log Transformer on synthetic sequences and export artifacts.

Objectives (LogBERT / arXiv:2103.04475):
  - Masked log-key language modeling (MLM) on Drain3-style template IDs
  - Sequence corruption classification head

Exports ONNX + Platt calibrator via black_onyx_calibration.
"""

from __future__ import annotations

import argparse
import json
import random
from pathlib import Path

import numpy as np
import torch
from black_onyx_calibration import fit_platt, save_calibrator
from log_model.model import LogTransformer, LogTransformerConfig
from log_model.vocab import TemplateVocab, severity_id
from torch import nn
from torch.utils.data import DataLoader, Dataset

NORMAL_TEMPLATES = [
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
]

CORRUPT_TEMPLATES = [
    "tpl-privilege-change",
    "tpl-shell-exec",
    "tpl-novel-unknown",
    "tpl-external-connect",
]

SEVERITIES = ["INFO", "INFO", "INFO", "WARN", "ERROR"]


def load_dataset(path: Path, vocab: TemplateVocab) -> list[dict]:
    """Load labeled platform ``logs.features`` sequences from JSONL."""
    rows: list[dict] = []
    labels: set[int] = set()
    for line_number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not raw.strip():
            continue
        row = json.loads(raw)
        if not isinstance(row, dict):
            raise TypeError(f"line {line_number}: expected an object")
        label = row.get("label")
        if label not in {0, 1}:
            raise ValueError(f"line {line_number}: label must be 0 or 1")
        events = row.get("events") or row.get("sequence")
        if not isinstance(events, list) or not events:
            raise ValueError(f"line {line_number}: events/sequence must be non-empty")
        templates: list[str] = []
        severities: list[str] = []
        for event in events:
            if isinstance(event, str):
                template_id = event
                severity = "INFO"
            elif isinstance(event, dict):
                template_id = str(event.get("template_id") or "")
                severity = str(event.get("severity") or "INFO").upper()
            else:
                raise TypeError(f"line {line_number}: every event must be an object or template id")
            if not template_id:
                raise ValueError(f"line {line_number}: template_id is required")
            vocab.add(template_id)
            templates.append(template_id)
            severities.append(severity)
        labels.add(int(label))
        rows.append({"templates": templates, "severities": severities, "label": int(label)})
    if not rows:
        raise ValueError("dataset must contain at least one row")
    if len(labels) < 2:
        raise ValueError("dataset must contain both label classes")
    return rows


def _corrupt(seq: list[str]) -> list[str]:
    mode = random.choice(["delete", "insert", "reorder", "replace", "novel"])
    out = list(seq)
    if mode == "delete" and len(out) > 4:
        del out[random.randrange(len(out))]
    elif mode == "insert":
        out.insert(random.randrange(len(out) + 1), random.choice(CORRUPT_TEMPLATES))
    elif mode == "reorder" and len(out) > 3:
        i = random.randrange(len(out) - 1)
        out[i], out[i + 1] = out[i + 1], out[i]
    elif mode == "replace":
        out[random.randrange(len(out))] = random.choice(CORRUPT_TEMPLATES)
    else:
        out[random.randrange(len(out))] = "tpl-privilege-change"
    return out


def generate_sequences(
    vocab: TemplateVocab, n_normal: int = 200, n_corrupt: int = 200, seq_len: int = 16
) -> list[dict]:
    for t in NORMAL_TEMPLATES + CORRUPT_TEMPLATES:
        vocab.add(t)
    rows: list[dict] = []
    for _ in range(n_normal):
        templates = [random.choice(NORMAL_TEMPLATES) for _ in range(seq_len)]
        rows.append({"templates": templates, "label": 0})
    for _ in range(n_corrupt):
        templates = [random.choice(NORMAL_TEMPLATES) for _ in range(seq_len)]
        templates = _corrupt(templates)
        rows.append({"templates": templates, "label": 1})
    random.shuffle(rows)
    return rows


class SeqDataset(Dataset):
    def __init__(self, rows: list[dict], vocab: TemplateVocab, max_len: int = 128) -> None:
        self.rows = rows
        self.vocab = vocab
        self.max_len = max_len

    def __len__(self) -> int:
        return len(self.rows)

    def __getitem__(self, idx: int) -> dict[str, torch.Tensor]:
        row = self.rows[idx]
        templates = row["templates"][: self.max_len]
        ids = [self.vocab.encode(t) for t in templates]
        row_severities = row.get("severities") or []
        sev = [
            severity_id(row_severities[pos] if pos < len(row_severities) else random.choice(SEVERITIES))
            for pos, _template in enumerate(templates)
        ]
        pad = self.max_len - len(ids)
        attention = [1] * len(ids) + [0] * pad
        ids = ids + [self.vocab.pad_id] * pad
        sev = sev + [0] * pad
        return {
            "input_ids": torch.tensor(ids, dtype=torch.long),
            "severity_ids": torch.tensor(sev, dtype=torch.long),
            "attention_mask": torch.tensor(attention, dtype=torch.long),
            "label": torch.tensor(row["label"], dtype=torch.float32),
        }


def mask_inputs(
    input_ids: torch.Tensor, attention_mask: torch.Tensor, mask_token_id: int, pad_id: int
) -> tuple[torch.Tensor, torch.Tensor]:
    """LogBERT MLM: randomly mask ~15% of non-padding template tokens."""
    labels = input_ids.clone()
    probability_matrix = torch.full(labels.shape, 0.15)
    masked = torch.bernoulli(probability_matrix).bool()
    masked &= attention_mask.bool()
    labels[~masked] = -100
    input_ids = input_ids.clone()
    input_ids[masked] = mask_token_id
    input_ids[attention_mask == 0] = pad_id
    return input_ids, labels


def _raw_anomaly_score(
    model: LogTransformer,
    batch: dict[str, torch.Tensor],
) -> list[float]:
    """Uncalibrated score from corruption logit + mean token NLL (no MLM mask)."""
    model.eval()
    with torch.no_grad():
        out = model(batch["input_ids"], batch["severity_ids"], batch["attention_mask"])
        corr = torch.sigmoid(out["corruption_logit"]).cpu().numpy()
        logits = out["token_logits"]
        ids = batch["input_ids"]
        mask = batch["attention_mask"]
        scores: list[float] = []
        for i in range(ids.shape[0]):
            nlls: list[float] = []
            for pos in range(ids.shape[1]):
                if int(mask[i, pos].item()) == 0:
                    continue
                row = logits[i, pos]
                exp = torch.exp(row - row.max())
                probs = exp / exp.sum()
                tid = int(ids[i, pos].item())
                prob = float(probs[tid].item()) if tid < probs.numel() else 1e-9
                nlls.append(-float(np.log(max(prob, 1e-9))))
            masked_loss = float(np.mean(nlls)) if nlls else 0.0
            scores.append(0.45 * masked_loss + 0.20 * float(corr[i]))
        return scores


def train_model(
    *,
    artifacts_dir: Path,
    epochs: int = 2,
    batch_size: int = 16,
    n_normal: int = 128,
    n_corrupt: int = 128,
    seq_len: int = 16,
    seed: int = 7,
    dataset_path: Path | None = None,
) -> Path:
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)

    artifacts_dir.mkdir(parents=True, exist_ok=True)
    vocab = TemplateVocab()
    rows = (
        load_dataset(dataset_path, vocab)
        if dataset_path
        else generate_sequences(vocab, n_normal=n_normal, n_corrupt=n_corrupt, seq_len=seq_len)
    )
    dataset = SeqDataset(rows, vocab, max_len=128)
    loader = DataLoader(dataset, batch_size=batch_size, shuffle=True)

    config = LogTransformerConfig(vocab_size=len(vocab.token_to_id))
    model = LogTransformer(config)
    optim = torch.optim.AdamW(model.parameters(), lr=1e-3)
    mlm_loss_fn = nn.CrossEntropyLoss(ignore_index=-100)
    bce = nn.BCEWithLogitsLoss()

    model.train()
    for epoch in range(epochs):
        total = 0.0
        for batch in loader:
            # LogBERT joint loss: MLM + corruption BCE
            masked_ids, mlm_labels = mask_inputs(
                batch["input_ids"],
                batch["attention_mask"],
                config.mask_token_id,
                config.pad_token_id,
            )
            out = model(masked_ids, batch["severity_ids"], batch["attention_mask"])
            mlm_loss = mlm_loss_fn(out["token_logits"].view(-1, config.vocab_size), mlm_labels.view(-1))
            corr_loss = bce(out["corruption_logit"], batch["label"])
            loss = mlm_loss + corr_loss
            optim.zero_grad()
            loss.backward()
            optim.step()
            total += float(loss.item())
        print(f"epoch={epoch + 1} loss={total / max(len(loader), 1):.4f}")

    model.eval()
    ckpt_path = artifacts_dir / "model.pt"
    torch.save(model.state_dict(), ckpt_path)

    # Fit Platt calibrator on hold-out raw scores vs corruption labels.
    raw_scores: list[float] = []
    labels: list[int] = []
    cal_loader = DataLoader(dataset, batch_size=batch_size, shuffle=False)
    for batch in cal_loader:
        raw_scores.extend(_raw_anomaly_score(model, batch))
        labels.extend(int(v) for v in batch["label"].cpu().numpy().tolist())
    artifact = fit_platt(raw_scores, labels)
    save_calibrator(artifact, artifacts_dir / "calibration.json")

    # Export ONNX
    onnx_path = artifacts_dir / "model.onnx"
    dummy_ids = torch.zeros(1, 128, dtype=torch.long)
    dummy_sev = torch.zeros(1, 128, dtype=torch.long)
    dummy_mask = torch.ones(1, 128, dtype=torch.long)

    class ExportWrapper(nn.Module):
        def __init__(self, inner: LogTransformer) -> None:
            super().__init__()
            self.inner = inner

        def forward(
            self,
            input_ids: torch.Tensor,
            severity_ids: torch.Tensor,
            attention_mask: torch.Tensor,
        ) -> tuple[torch.Tensor, torch.Tensor]:
            out = self.inner(input_ids, severity_ids, attention_mask)
            return out["token_logits"], out["corruption_logit"]

    wrapper = ExportWrapper(model)
    wrapper.eval()
    torch.onnx.export(
        wrapper,
        (dummy_ids, dummy_sev, dummy_mask),
        str(onnx_path),
        input_names=["input_ids", "severity_ids", "attention_mask"],
        output_names=["token_logits", "corruption_logit"],
        dynamic_axes={
            "input_ids": {0: "batch"},
            "severity_ids": {0: "batch"},
            "attention_mask": {0: "batch"},
            "token_logits": {0: "batch"},
            "corruption_logit": {0: "batch"},
        },
        opset_version=17,
        dynamo=False,
    )

    vocab.save(artifacts_dir / "vocab.json")
    config_payload = {
        "model_name": "log-transformer",
        "model_version": "0.1.0",
        "feature_version": "1.0",
        "training": "logbert-mlm+corruption",
        "model": config.to_dict(),
    }
    (artifacts_dir / "config.json").write_text(json.dumps(config_payload, indent=2), encoding="utf-8")
    (artifacts_dir / "thresholds.json").write_text(
        json.dumps({"medium": 0.6, "high": 0.8, "critical": 0.93}, indent=2),
        encoding="utf-8",
    )
    print(f"wrote artifacts to {artifacts_dir}")
    return artifacts_dir


def main() -> None:
    parser = argparse.ArgumentParser(description="Train LogBERT-style log anomaly model (MLM + corruption, synthetic)")
    parser.add_argument(
        "--artifacts-dir",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "artifacts",
    )
    parser.add_argument("--epochs", type=int, default=2)
    parser.add_argument("--batch-size", type=int, default=16)
    parser.add_argument("--n-normal", type=int, default=128)
    parser.add_argument("--n-corrupt", type=int, default=128)
    parser.add_argument("--seq-len", type=int, default=16)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument(
        "--dataset",
        type=Path,
        help="JSONL dataset of labeled platform logs.features sequences",
    )
    args = parser.parse_args()
    train_model(
        artifacts_dir=args.artifacts_dir,
        epochs=args.epochs,
        batch_size=args.batch_size,
        n_normal=args.n_normal,
        n_corrupt=args.n_corrupt,
        seq_len=args.seq_len,
        seed=args.seed,
        dataset_path=args.dataset,
    )


if __name__ == "__main__":
    main()
