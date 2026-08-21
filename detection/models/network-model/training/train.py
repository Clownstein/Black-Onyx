from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import torch
from black_onyx_calibration import fit_platt, save_calibrator
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

    raw_scores: list[float] = []
    labels: list[int] = []
    loaded = load_dataset(args.dataset) if args.dataset else None

    for epoch in range(args.epochs):
        x, y, mask = loaded if loaded is not None else synthetic_batch()
        opt.zero_grad()
        pred = model(x, mask)
        loss = loss_fn(pred, y)
        loss.backward()
        opt.step()
        print(f"epoch={epoch} loss={loss.item():.4f}")
        if epoch == args.epochs - 1:
            raw_scores = [float(v) for v in pred.detach().cpu().numpy().tolist()]
            labels = [int(v) for v in y.cpu().numpy().tolist()]

    ckpt = args.out / "network_model.pt"
    torch.save(model.state_dict(), ckpt)
    onnx_path = args.out / "network_model.onnx"
    try:
        export_onnx(model, onnx_path)
        print(f"exported {onnx_path}")
    except Exception as exc:  # noqa: BLE001
        print(f"onnx export skipped: {exc}")

    if raw_scores and labels:
        save_calibrator(fit_platt(raw_scores, labels), args.out / "calibration.json")
    else:
        save_calibrator(fit_platt([0.1, 0.9], [0, 1]), args.out / "calibration.json")

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
