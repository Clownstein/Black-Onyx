from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import joblib
import numpy as np
from black_onyx_calibration import Calibrator, brier_score, fit_platt, save_calibrator
from metrics_model.model import (
    METRIC_ORDER,
    IsolationForestFallback,
    MultivariateMetricTransformer,
    window_to_tensor,
)


def load_dataset(path: Path) -> tuple[np.ndarray, np.ndarray]:
    """Load labeled platform ``metrics.features`` windows from JSONL."""
    windows: list[np.ndarray] = []
    labels: list[int] = []
    for line_number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not raw.strip():
            continue
        row = json.loads(raw)
        if not isinstance(row, dict):
            raise TypeError(f"line {line_number}: expected an object")
        label = row.get("label")
        if label not in {0, 1}:
            raise ValueError(f"line {line_number}: label must be 0 or 1")
        values = row.get("values")
        if not isinstance(values, dict):
            raise TypeError(f"line {line_number}: values must be an object")
        missing = [name for name in METRIC_ORDER if name not in values]
        if missing:
            raise ValueError(f"line {line_number}: missing metrics {', '.join(missing)}")
        if any(not isinstance(values[name], list) for name in METRIC_ORDER):
            raise ValueError(f"line {line_number}: every metric series must be a list")
        lengths = {len(values[name]) for name in METRIC_ORDER}
        if len(lengths) != 1 or not lengths or next(iter(lengths)) < 4:
            raise ValueError(f"line {line_number}: metric series must share a length of at least 4")
        windows.append(window_to_tensor(row, length=60))
        labels.append(int(label))
    if not windows:
        raise ValueError("dataset must contain at least one row")
    if len(set(labels)) < 2:
        raise ValueError("dataset must contain both label classes")
    return np.stack(windows).astype(np.float32), np.asarray(labels, dtype=np.float32)


def load_dataset_splits(path: Path) -> dict[str, tuple[np.ndarray, np.ndarray]]:
    buckets: dict[str, list[dict]] = {name: [] for name in ("train", "validation", "test")}
    assets: dict[tuple[str, str], str] = {}
    samples: set[str] = set()
    for line_number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not raw.strip():
            continue
        row = json.loads(raw)
        split = row.get("split")
        if split not in buckets:
            raise ValueError(f"line {line_number}: train, validation, or test split required")
        if any(not isinstance(row.get(key), str) or not row[key].strip()
               for key in ("sample_id", "tenant_id", "asset_id", "label_source")):
            raise ValueError(f"line {line_number}: sample, entity, and label provenance required")
        if row["sample_id"] in samples:
            raise ValueError("duplicate sample across dataset splits")
        samples.add(row["sample_id"])
        entity = (row["tenant_id"], row["asset_id"])
        if entity in assets and assets[entity] != split:
            raise ValueError("tenant/asset group crosses dataset splits")
        assets[entity] = split
        buckets[split].append(row)
    partitions = {}
    for split, rows in buckets.items():
        if {row.get("label") for row in rows} != {0, 1}:
            raise ValueError(f"{split} split requires both label classes")
        windows, labels = [], []
        for row in rows:
            values = row.get("values")
            if not isinstance(values, dict) or any(name not in values for name in METRIC_ORDER):
                raise ValueError(f"{split} split has missing metric values")
            if any(not isinstance(values[name], list) for name in METRIC_ORDER):
                raise ValueError(f"{split} split has invalid metric series")
            lengths = {len(values[name]) for name in METRIC_ORDER}
            if len(lengths) != 1:
                raise ValueError(f"{split} split has invalid metric series")
            if next(iter(lengths)) < 4:
                raise ValueError(f"{split} split has too few metric observations")
            windows.append(window_to_tensor(row, length=60))
            labels.append(row["label"])
        partitions[split] = np.stack(windows).astype(np.float32), np.asarray(labels, dtype=np.float32)
    return partitions


def evaluate(probs: list[float], labels: list[int]) -> dict:
    decisions = [int(prob >= 0.5) for prob in probs]
    tp = sum(p == 1 and y == 1 for p, y in zip(decisions, labels))
    fp = sum(p == 1 and y == 0 for p, y in zip(decisions, labels))
    fn = sum(p == 0 and y == 1 for p, y in zip(decisions, labels))
    tn = len(labels) - tp - fp - fn
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    return {
        "split": "test", "sample_count": len(labels), "positive_count": sum(labels),
        "threshold": 0.5, "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": precision, "recall": recall,
        "f1": 2 * precision * recall / (precision + recall) if precision + recall else 0.0,
        "accuracy": (tp + tn) / len(labels), "brier_score": brier_score(probs, labels),
        "calibration_split": "validation", "training_split": "train",
        "external_validation": False,
    }


def synthetic_windows(n: int = 128, t: int = 60, f: int = 14) -> tuple[np.ndarray, np.ndarray]:
    rng = np.random.default_rng(42)
    x = rng.random((n, t, f), dtype=np.float32) * 0.3
    # Label windows with elevated error_rate (channel 6) / latency (channel 8)
    y = np.zeros(n, dtype=np.float32)
    y[n // 2 :] = 1.0
    # Inject clearer anomalies into half of positive class
    for i in range(n):
        if y[i] > 0.5:
            x[i, t // 2 :, 6] = 0.8 + rng.random(t - t // 2) * 0.2
            x[i, t // 2 :, 8] = 0.7 + rng.random(t - t // 2) * 0.3
            x[i, t // 2 :, 12] = 0.85  # db.pool.utilization value channel
    return x, y


def export_onnx(model: MultivariateMetricTransformer, path: Path) -> None:
    import torch

    model.eval()
    dummy = torch.zeros(1, model.window_length, model.input_dim)

    class ScoreOnly(torch.nn.Module):
        def __init__(self, inner: MultivariateMetricTransformer) -> None:
            super().__init__()
            self.inner = inner

        def forward(self, window: torch.Tensor) -> torch.Tensor:
            return self.inner(window)

    wrapped = ScoreOnly(model)
    torch.onnx.export(
        wrapped,
        dummy,
        str(path),
        input_names=["window"],
        output_names=["score"],
        dynamic_axes={"window": {0: "batch"}, "score": {0: "batch"}},
        opset_version=17,
        dynamo=False,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Train TranAD-style metrics model + IsolationForest")
    parser.add_argument("--epochs", type=int, default=5)
    parser.add_argument(
        "--out",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "artifacts",
    )
    parser.add_argument(
        "--dataset",
        type=Path,
        help="JSONL dataset of labeled platform metrics.features windows",
    )
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)

    if args.dataset:
        partitions = load_dataset_splits(args.dataset)
    else:
        x_np, y_np = synthetic_windows()
        partitions = {}
        rng = np.random.default_rng(7)
        selected: dict[str, list[int]] = {name: [] for name in ("train", "validation", "test")}
        for label in (0, 1):
            indices = np.flatnonzero(y_np.astype(int) == label)
            if len(indices) < 3:
                raise ValueError("synthetic windows need at least three samples per class")
            rng.shuffle(indices)
            train_end = max(1, int(len(indices) * 0.6))
            validation_end = max(train_end + 1, int(len(indices) * 0.8))
            for name, subset in zip(
                ("train", "validation", "test"),
                (indices[:train_end], indices[train_end:validation_end], indices[validation_end:]),
            ):
                selected[name].extend(int(index) for index in subset)
        for name, indices in selected.items():
            partitions[name] = x_np[indices], y_np[indices]
    x_np, y_np = partitions["train"]

    # Always train IsolationForest fallback artifact.
    forest = IsolationForestFallback()
    forest.fit(x_np)
    joblib.dump(forest, args.out / "isolation_forest.joblib")

    import torch
    from torch import nn

    if args.epochs < 1:
        raise ValueError("epochs must be at least one")
    model = MultivariateMetricTransformer()
    opt = torch.optim.AdamW(model.parameters(), lr=1e-3)
    bce = nn.BCELoss()
    mse = nn.MSELoss()
    x = torch.from_numpy(x_np)
    y = torch.from_numpy(y_np)
    for epoch in range(args.epochs):
        opt.zero_grad()
        recon = model.reconstruct(x)
        recon_loss = mse(recon, x)
        pred = model(x)
        score_loss = bce(pred, y)
        loss = recon_loss + score_loss
        loss.backward()
        opt.step()
        print(f"epoch={epoch} loss={loss.item():.4f} recon={recon_loss.item():.4f}")

    model.eval()
    def score_split(name: str) -> tuple[list[float], list[int]]:
        windows, labels = partitions[name]
        with torch.no_grad():
            scores = model(torch.from_numpy(windows)).cpu().numpy().tolist()
        return [float(score) for score in scores], [int(label) for label in labels.tolist()]

    validation_scores, validation_labels = score_split("validation")
    art = fit_platt(validation_scores, validation_labels)
    if art.method == "identity":
        raise RuntimeError("validation calibration did not fit")
    save_calibrator(art, args.out / "calibration.json")
    test_scores, test_labels = score_split("test")
    probs = Calibrator(art).calibrate_many(test_scores).tolist()
    metrics = evaluate(probs, test_labels)
    metrics["dataset_kind"] = "provided_labeled" if args.dataset else "synthetic_smoke"
    if args.dataset:
        metrics["dataset_sha256"] = hashlib.sha256(args.dataset.read_bytes()).hexdigest()
    (args.out / "metrics.json").write_text(json.dumps(metrics, indent=2) + "\n", encoding="utf-8")

    ckpt = args.out / "metrics_model.pt"
    torch.save(model.state_dict(), ckpt)
    onnx_path = args.out / "metrics_model.onnx"
    export_onnx(model, onnx_path)
    print(f"exported {onnx_path}")
    print(f"saved {ckpt}")

    (args.out / "config.json").write_text(
        json.dumps(
            {
                "model_name": "metrics-model",
                "model_version": "1.2.0",
                "architecture": "tranad",
                "hidden": 96,
                "layers": 3,
                "heads": 4,
                "window": 60,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    (args.out / "thresholds.json").write_text(
        json.dumps({"medium": 0.6, "high": 0.8, "critical": 0.93}, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"artifacts written to {args.out}")


if __name__ == "__main__":
    main()
