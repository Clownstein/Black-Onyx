from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import numpy as np
import torch
from black_onyx_calibration import Calibrator, brier_score, fit_platt, save_calibrator
from network_model.model import FEATURE_DIM, FlowTransformer, flows_to_tensor
from torch import nn


def load_dataset(path: Path) -> tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
    """Load labeled ``network.features`` windows from JSONL."""
    features: list[np.ndarray] = []
    masks: list[np.ndarray] = []
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
        flows = row.get("flows") or row.get("flow_sample")
        if not isinstance(flows, list) or not flows:
            raise ValueError(f"line {line_number}: flows/flow_sample must be non-empty")
        if any(not isinstance(flow, dict) for flow in flows):
            raise ValueError(f"line {line_number}: every flow must be an object")
        array, mask = flows_to_tensor(flows, max_len=256)
        features.append(array)
        masks.append(mask)
        labels.append(int(label))
    if not features:
        raise ValueError("dataset must contain at least one row")
    if len(set(labels)) < 2:
        raise ValueError("dataset must contain both label classes")
    return (
        torch.from_numpy(np.stack(features)),
        torch.tensor(labels, dtype=torch.float32),
        torch.from_numpy(np.stack(masks)),
    )


def load_dataset_splits(path: Path) -> dict[str, tuple[torch.Tensor, torch.Tensor, torch.Tensor]]:
    """Read explicit partitions and reject repeated assets across evaluation boundaries."""
    buckets: dict[str, list[dict]] = {split: [] for split in ("train", "validation", "test")}
    assets: dict[tuple[str, str], str] = {}
    samples: set[str] = set()
    for line_number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not raw.strip():
            continue
        row = json.loads(raw)
        split = row.get("split")
        if split not in buckets:
            raise ValueError(f"line {line_number}: train, validation, or test split is required")
        if any(not isinstance(row.get(key), str) or not row[key].strip()
               for key in ("sample_id", "tenant_id", "asset_id", "label_source")):
            raise ValueError(f"line {line_number}: sample, entity, and label provenance required")
        if row["sample_id"] in samples:
            raise ValueError("duplicate sample across dataset splits")
        samples.add(row["sample_id"])
        asset = (row["tenant_id"], row["asset_id"])
        if asset in assets and assets[asset] != split:
            raise ValueError("tenant/asset group crosses dataset splits")
        assets[asset] = split
        buckets[split].append(row)

    partitions = {}
    for split, rows in buckets.items():
        if {row.get("label") for row in rows} != {0, 1}:
            raise ValueError(f"{split} split requires both label classes")
        features, labels, masks = [], [], []
        for row in rows:
            flows = row.get("flows") or row.get("flow_sample")
            if not isinstance(flows, list) or not flows or any(not isinstance(flow, dict) for flow in flows):
                raise ValueError(f"{split} split has invalid flows")
            array, mask = flows_to_tensor(flows, max_len=256)
            features.append(array)
            masks.append(mask)
            labels.append(row["label"])
        partitions[split] = (
            torch.from_numpy(np.stack(features)),
            torch.tensor(labels, dtype=torch.float32),
            torch.from_numpy(np.stack(masks)),
        )
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


def synthetic_batch(n: int = 64, t: int = 32, f: int = FEATURE_DIM) -> tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
    x = torch.randn(n, t, f)
    # label: high avg on failed/external dims + elevated dns entropy / sni rarity
    y = ((x[:, :, 6].mean(dim=1) + x[:, :, 7].mean(dim=1) + 0.5 * x[:, :, 16].mean(dim=1)) > 0.1).float()
    mask = torch.zeros(n, t, dtype=torch.bool)
    return x, y, mask


def export_onnx(model: FlowTransformer, path: Path, max_len: int = 256) -> None:
    model.eval()
    dummy = torch.zeros(1, max_len, model.input_dim)
    torch.onnx.export(
        model,
        (dummy, None),
        str(path),
        input_names=["features"],
        output_names=["score"],
        dynamic_axes={"features": {0: "batch", 1: "time"}, "score": {0: "batch"}},
        opset_version=17,
        dynamo=False,
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--epochs", type=int, default=3)
    parser.add_argument("--out", type=Path, default=Path("artifacts"))
    parser.add_argument(
        "--dataset",
        type=Path,
        help="JSONL dataset of labeled platform network.features windows",
    )
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)

    model = FlowTransformer()
    opt = torch.optim.AdamW(model.parameters(), lr=1e-3)
    loss_fn = nn.BCELoss()

    if args.dataset:
        partitions = load_dataset_splits(args.dataset)
    else:
        x, y, mask = synthetic_batch()
        partitions = {}
        rng = np.random.default_rng(7)
        split_indices: dict[str, list[int]] = {name: [] for name in ("train", "validation", "test")}
        for label in (0, 1):
            indices = np.flatnonzero(y.numpy().astype(int) == label)
            if len(indices) < 3:
                raise ValueError("synthetic batch needs at least three samples per class")
            rng.shuffle(indices)
            train_end = max(1, int(len(indices) * 0.6))
            validation_end = max(train_end + 1, int(len(indices) * 0.8))
            for name, selected in zip(
                ("train", "validation", "test"),
                (indices[:train_end], indices[train_end:validation_end], indices[validation_end:]),
            ):
                split_indices[name].extend(int(index) for index in selected)
        for name, indices in split_indices.items():
            partitions[name] = (x[indices], y[indices], mask[indices])

    for epoch in range(args.epochs):
        x, y, mask = partitions["train"]
        opt.zero_grad()
        pred = model(x, mask)
        loss = loss_fn(pred, y)
        loss.backward()
        opt.step()
        print(f"epoch={epoch} loss={loss.item():.4f}")

    def score_split(name: str) -> tuple[list[float], list[int]]:
        model.eval()
        x, y, mask = partitions[name]
        with torch.no_grad():
            scores = model(x, mask).cpu().numpy().tolist()
        return [float(score) for score in scores], [int(label) for label in y.tolist()]

    validation_scores, validation_labels = score_split("validation")
    artifact = fit_platt(validation_scores, validation_labels)
    if artifact.method == "identity":
        raise RuntimeError("validation calibration did not fit")
    save_calibrator(artifact, args.out / "calibration.json")
    test_scores, test_labels = score_split("test")
    probs = Calibrator(artifact).calibrate_many(test_scores).tolist()
    metrics = evaluate(probs, test_labels)
    metrics["dataset_kind"] = "provided_labeled" if args.dataset else "synthetic_smoke"
    if args.dataset:
        metrics["dataset_sha256"] = hashlib.sha256(args.dataset.read_bytes()).hexdigest()
    (args.out / "metrics.json").write_text(json.dumps(metrics, indent=2) + "\n", encoding="utf-8")

    ckpt = args.out / "network_model.pt"
    torch.save(model.state_dict(), ckpt)
    onnx_path = args.out / "network_model.onnx"
    try:
        export_onnx(model, onnx_path)
        print(f"exported {onnx_path}")
    except Exception as exc:  # noqa: BLE001
        print(f"onnx export skipped: {exc}")

    (args.out / "config.json").write_text(
        json.dumps(
            {
                "model_name": "network-model",
                "model_version": "1.4.0",
                "feature_dim": FEATURE_DIM,
                "features": [
                    "src_port",
                    "dst_port",
                    "tcp",
                    "udp",
                    "log_bytes",
                    "log_packets",
                    "failed",
                    "external",
                    "egress",
                    "ingress",
                    "peer_hash",
                    "has_bytes",
                    "sensitive_port",
                    "web_port",
                    "ja3_bucket",
                    "ja4_bucket",
                    "sni_rarity",
                    "dns_entropy",
                    "has_tls",
                    "has_dns",
                ],
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    (args.out / "thresholds.json").write_text(
        json.dumps({"medium": 0.72, "high": 0.86, "critical": 0.95}, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"saved {ckpt}")


if __name__ == "__main__":
    main()
