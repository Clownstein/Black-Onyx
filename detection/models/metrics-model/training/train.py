from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib
import numpy as np
from black_onyx_calibration import fit_platt, save_calibrator
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


def synthetic_windows(n: int = 128, t: int = 60, f: int = 14) -> tuple[np.ndarray, np.ndarray]:
    rng = np.random.default_rng(42)
    x = rng.random((n, t, f), dtype=np.float32) * 0.3
    # Label windows with elevated error_rate (channel 6) / latency (channel 8)
    y = ((x[:, :, 6].mean(axis=1) + x[:, :, 8].mean(axis=1)) > 0.35).astype(np.float32)
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

    x_np, y_np = load_dataset(args.dataset) if args.dataset else synthetic_windows()

    # Always train IsolationForest fallback artifact.
    forest = IsolationForestFallback()
    forest.fit(x_np)
    joblib.dump(forest, args.out / "isolation_forest.joblib")

    raw_for_cal: list[float] = []
    labels_for_cal: list[int] = list(y_np.astype(int).tolist())

    try:
        import torch
        from torch import nn

        model = MultivariateMetricTransformer()
        opt = torch.optim.AdamW(model.parameters(), lr=1e-3)
        bce = nn.BCELoss()
        mse = nn.MSELoss()
        x = torch.from_numpy(x_np)
        y = torch.from_numpy(y_np)

        for epoch in range(args.epochs):
            opt.zero_grad()
            # TranAD: reconstruction + anomaly score supervision
            recon = model.reconstruct(x)
            recon_loss = mse(recon, x)
            pred = model(x)
            score_loss = bce(pred, y)
            loss = recon_loss + score_loss
            loss.backward()
            opt.step()
            print(f"epoch={epoch} loss={loss.item():.4f} recon={recon_loss.item():.4f}")

        model.eval()
        with torch.no_grad():
            raw_for_cal = [float(v) for v in model(x).cpu().numpy().tolist()]

        ckpt = args.out / "metrics_model.pt"
        torch.save(model.state_dict(), ckpt)
        onnx_path = args.out / "metrics_model.onnx"
        try:
            export_onnx(model, onnx_path)
            print(f"exported {onnx_path}")
        except Exception as exc:  # noqa: BLE001
            print(f"onnx export skipped: {exc}")
        print(f"saved {ckpt}")
    except Exception as exc:  # noqa: BLE001
        print(f"transformer training skipped: {exc}")
        # Fall back to IsolationForest scores for calibration
        for i in range(len(x_np)):
            raw_for_cal.append(float(forest.score(x_np[i])))

    if raw_for_cal and labels_for_cal:
        art = fit_platt(raw_for_cal, labels_for_cal)
        save_calibrator(art, args.out / "calibration.json")
    else:
        save_calibrator(
            fit_platt([0.1, 0.9], [0, 1]),
            args.out / "calibration.json",
        )

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
