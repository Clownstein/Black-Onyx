#!/usr/bin/env python3
"""Load a calibration artifact and print ECE on synthetic labels.

Uses ``black_onyx_calibration`` helpers. Example:

  uv run python scripts/development/check_model_ece.py --calibration path/to/calibration.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "packages" / "black_onyx_calibration" / "src"))

from black_onyx_calibration import (  # noqa: E402
    expected_calibration_error,
    load_calibrator,
    save_calibrator,
)
from black_onyx_calibration.calibrator import CalibrationArtifact  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--calibration",
        type=Path,
        default=None,
        help="Path to calibration JSON (default: identity / synthetic platt)",
    )
    parser.add_argument("--n", type=int, default=200, help="Synthetic sample count")
    parser.add_argument("--seed", type=int, default=7)
    args = parser.parse_args(argv)

    rng = np.random.default_rng(args.seed)
    raw = rng.uniform(0, 1, size=args.n)
    # Synthetic labels correlated with raw scores.
    labels = (raw + rng.normal(0, 0.15, size=args.n) > 0.5).astype(int)

    if args.calibration and args.calibration.is_file():
        calibrator = load_calibrator(args.calibration)
    else:
        # Default: mild Platt identity-like artifact for demo.
        art = CalibrationArtifact(method="platt", scale=1.2, bias=-0.1)
        tmp = ROOT / "packages" / "black_onyx_calibration" / "artifacts" / "demo_calibration.json"
        tmp.parent.mkdir(parents=True, exist_ok=True)
        save_calibrator(art, tmp)
        calibrator = load_calibrator(tmp)
        print(f"wrote demo calibration -> {tmp}")

    probs = calibrator.calibrate_many(raw)
    ece = expected_calibration_error(probs, labels)
    print(json.dumps({"n": args.n, "ece": round(float(ece), 6), "method": calibrator.artifact.method}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
