#!/usr/bin/env python3
"""Quick training entrypoint for CI / local smoke (few epochs, small data)."""

from pathlib import Path

from training.train import train_model


def main() -> None:
    artifacts = Path(__file__).resolve().parents[1] / "artifacts"
    train_model(
        artifacts_dir=artifacts,
        epochs=1,
        batch_size=8,
        n_normal=64,
        n_corrupt=64,
        seq_len=12,
        seed=7,
    )


if __name__ == "__main__":
    main()
