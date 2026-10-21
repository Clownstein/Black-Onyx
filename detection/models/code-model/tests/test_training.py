import json
from pathlib import Path

import pytest

from training.train import evaluate, load_dataset, split_dataset, synthetic_dataset


EXAMPLE = Path(__file__).resolve().parents[1] / "training" / "examples" / "platform_changes.jsonl"


def test_code_training_uses_disjoint_labeled_splits():
    samples, labels = load_dataset(EXAMPLE)
    partitions = split_dataset(samples, labels)
    assert {name: len(value[1]) for name, value in partitions.items()} == {
        "train": 4, "validation": 2, "test": 2,
    }
    metrics = evaluate([0.1, 0.9], [0, 1])
    assert metrics["f1"] == 1.0
    synthetic, synthetic_labels = synthetic_dataset()
    synthetic_partitions = split_dataset(synthetic, synthetic_labels, synthetic=True)
    assert all(set(partition[1]) == {0, 1} for partition in synthetic_partitions.values())


def test_code_training_rejects_file_lineage_leakage(tmp_path):
    rows = [json.loads(line) for line in EXAMPLE.read_text(encoding="utf-8").splitlines()]
    rows[2]["files_changed"] = rows[0]["files_changed"]
    dataset = tmp_path / "leaking.jsonl"
    dataset.write_text("\n".join(json.dumps(row) for row in rows), encoding="utf-8")
    samples, labels = load_dataset(dataset)
    with pytest.raises(ValueError, match="lineage crosses"):
        split_dataset(samples, labels)
