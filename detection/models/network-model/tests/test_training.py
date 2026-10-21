import json
from pathlib import Path

import pytest

from training.train import evaluate, load_dataset_splits


EXAMPLE = Path(__file__).resolve().parents[1] / "training" / "examples" / "platform_windows.jsonl"


def test_network_training_uses_disjoint_labeled_splits():
    partitions = load_dataset_splits(EXAMPLE)
    assert {name: len(value[1]) for name, value in partitions.items()} == {
        "train": 4, "validation": 2, "test": 2,
    }
    metrics = evaluate([0.2, 0.8], [0, 1])
    assert metrics["sample_count"] == 2
    assert metrics["tp"] == metrics["tn"] == 1


def test_network_training_rejects_asset_leakage(tmp_path):
    rows = [json.loads(line) for line in EXAMPLE.read_text(encoding="utf-8").splitlines()]
    rows[2]["asset_id"] = rows[0]["asset_id"]
    dataset = tmp_path / "leaking.jsonl"
    dataset.write_text("\n".join(json.dumps(row) for row in rows), encoding="utf-8")
    with pytest.raises(ValueError, match="crosses dataset splits"):
        load_dataset_splits(dataset)
