from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

import numpy as np
from black_onyx_calibration import Calibrator, brier_score, fit_platt
from code_model.features import feature_vector
from code_model.scorer import ChangeRiskModel


def load_dataset(path: Path) -> tuple[list[dict[str, Any]], list[int]]:
    """Load platform-shaped ``code.features`` rows from JSONL.

    Each row carries the native model request fields plus a binary ``label``.
    Optional provenance fields such as ``sample_id`` and ``split`` are retained
    but ignored by feature extraction.
    """
    samples: list[dict[str, Any]] = []
    labels: list[int] = []
    for line_number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not raw.strip():
            continue
        row = json.loads(raw)
        if not isinstance(row, dict):
            raise TypeError(f"line {line_number}: expected an object")
        label = row.pop("label", None)
        if label not in {0, 1}:
            raise ValueError(f"line {line_number}: label must be 0 or 1")
        if not isinstance(row.get("files_changed"), list):
            raise TypeError(f"line {line_number}: files_changed must be a list")
        if not isinstance(row.get("scanner_findings", []), list):
            raise TypeError(f"line {line_number}: scanner_findings must be a list")
        diff_text = row.get("diff_text") or (row.get("text_features") or {}).get("diff_text")
        if not isinstance(diff_text, str) or not diff_text:
            raise ValueError(f"line {line_number}: diff_text is required")
        row["diff_text"] = diff_text
        samples.append(row)
        labels.append(int(label))
    if not samples:
        raise ValueError("dataset must contain at least one row")
    if len(set(labels)) < 2:
        raise ValueError("dataset must contain both label classes")
    return samples, labels


def split_dataset(
    samples: list[dict[str, Any]], labels: list[int], *, synthetic: bool = False,
) -> dict[str, tuple[list[dict[str, Any]], list[int]]]:
    buckets: dict[str, tuple[list[dict[str, Any]], list[int]]] = {
        name: ([], []) for name in ("train", "validation", "test")
    }
    repositories: dict[str, str] = {}
    file_groups: dict[str, str] = {}
    sample_ids: set[str] = set()
    synthetic_groups: dict[int, dict[str, list[tuple[dict[str, Any], int]]]] = {0: {}, 1: {}}
    for sample, label in zip(samples, labels):
        if synthetic:
            fingerprint = hashlib.sha256(sample["diff_text"].encode("utf-8")).hexdigest()
            synthetic_groups[label].setdefault(fingerprint, []).append((sample, label))
            continue
        split = sample.get("split")
        if split not in buckets:
            raise ValueError("train, validation, or test split required for every code sample")
        sample_id = sample.get("sample_id")
        if not isinstance(sample_id, str) or not sample_id or sample_id in sample_ids:
            raise ValueError("unique sample_id required across code dataset splits")
        sample_ids.add(sample_id)
        repository = sample.get("repository")
        repo_hash = repository.get("repository_hash") if isinstance(repository, dict) else None
        if repo_hash:
            if repo_hash in repositories and repositories[repo_hash] != split:
                raise ValueError("repository crosses code dataset splits")
            repositories[repo_hash] = split
        for filename in sample["files_changed"]:
            if filename in file_groups and file_groups[filename] != split:
                raise ValueError("changed file lineage crosses code dataset splits")
            file_groups[filename] = split
        buckets[split][0].append(sample)
        buckets[split][1].append(label)
    if synthetic:
        for label, groups in synthetic_groups.items():
            if len(groups) < 3:
                raise ValueError("synthetic code examples need three distinct changes per class")
            ordered = list(groups.values())
            assignments = (["train"] * (len(ordered) - 2)) + ["validation", "test"]
            for group, split in zip(ordered, assignments):
                for sample, item_label in group:
                    buckets[split][0].append(sample)
                    buckets[split][1].append(item_label)
    for split, (_samples, subset_labels) in buckets.items():
        if set(subset_labels) != {0, 1}:
            raise ValueError(f"{split} split requires both label classes")
    return buckets


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


def synthetic_dataset() -> tuple[list[dict], list[int]]:
    risky = [
        {
            "diff_text": "+password = 'supersecret'\n+api_key='abcd'\n",
            "files_changed": ["auth/session.py"],
            "diff_stats": {"added_lines": 2, "removed_lines": 0},
            "scanner_findings": [
                {
                    "scanner": "semgrep",
                    "rule_id": "hardcoded-credentials",
                    "severity": "high",
                    "path": "auth/session.py",
                    "start_line": 1,
                    "end_line": 1,
                    "message": "hardcoded password",
                }
            ],
        },
        {
            "diff_text": "+eval(user_input)\n+subprocess.call(cmd, shell=True)\n",
            "files_changed": ["runner.py"],
            "diff_stats": {"added_lines": 2, "removed_lines": 0},
            "scanner_findings": [],
        },
        {
            "diff_text": "+token = 'sk-live-abc'\n+if not auth.check():\n+    pass\n",
            "files_changed": ["login/handler.py"],
            "diff_stats": {"added_lines": 3, "removed_lines": 1},
            "scanner_findings": [
                {
                    "scanner": "semgrep",
                    "rule_id": "secret-leak",
                    "severity": "high",
                    "path": "login/handler.py",
                    "start_line": 1,
                    "end_line": 1,
                    "message": "secret like token",
                }
            ],
        },
        {
            "diff_text": "+pickle.loads(blob)\n+shell=True\n",
            "files_changed": ["workers/job.py"],
            "diff_stats": {"added_lines": 2, "removed_lines": 0},
            "scanner_findings": [],
        },
    ]
    safe = [
        {
            "diff_text": "+def add(a, b):\n+    return a + b\n",
            "files_changed": ["math_utils.py"],
            "diff_stats": {"added_lines": 2, "removed_lines": 0},
            "scanner_findings": [],
        },
        {
            "diff_text": "+# improve logging\n+logger.info('ok')\n",
            "files_changed": ["app.py"],
            "diff_stats": {"added_lines": 2, "removed_lines": 0},
            "scanner_findings": [],
        },
        {
            "diff_text": "+x = y + 1\n+return x\n",
            "files_changed": ["svc.py"],
            "diff_stats": {"added_lines": 2, "removed_lines": 0},
            "scanner_findings": [],
        },
        {
            "diff_text": "+result = sorted(items)\n+return result\n",
            "files_changed": ["lib/sort.py"],
            "diff_stats": {"added_lines": 2, "removed_lines": 1},
            "scanner_findings": [],
        },
    ]
    samples = risky * 12 + safe * 12
    labels = [1] * (len(risky) * 12) + [0] * (len(safe) * 12)
    return samples, labels


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--out",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "artifacts",
    )
    parser.add_argument(
        "--dataset",
        type=Path,
        help="JSONL dataset in the platform code.features format; synthetic data is test-only fallback",
    )
    parser.add_argument(
        "--encoder",
        choices=("distil", "hf"),
        default="distil",
        help="Encoder backend: distil (hashed-token) or hf (CodeBERT when transformers installed)",
    )
    args = parser.parse_args()

    samples, labels = load_dataset(args.dataset) if args.dataset else synthetic_dataset()
    partitions = split_dataset(samples, labels, synthetic=args.dataset is None)
    train_samples, train_labels = partitions["train"]
    validation_samples, validation_labels = partitions["validation"]
    test_samples, test_labels = partitions["test"]
    model = ChangeRiskModel()
    model.fit(train_samples, train_labels, encoder=args.encoder)
    if model.model is None:
        raise RuntimeError("code scorer did not fit")

    def raw_scores(rows: list[dict[str, Any]]) -> list[float]:
        vectors = np.vstack([feature_vector(row) for row in rows])
        return [float(value) for value in model.model.predict_proba(vectors)[:, 1].tolist()]

    calibration = fit_platt(raw_scores(validation_samples), validation_labels)
    if calibration.method == "identity":
        raise RuntimeError("validation calibration did not fit")
    model.calibrator = Calibrator(calibration)
    probabilities = model.calibrator.calibrate_many(raw_scores(test_samples)).tolist()
    metrics = evaluate(probabilities, test_labels)
    metrics["dataset_kind"] = "provided_labeled" if args.dataset else "synthetic_smoke"
    if args.dataset:
        metrics["dataset_sha256"] = hashlib.sha256(args.dataset.read_bytes()).hexdigest()
    model.save(args.out)
    # The saved scorer must carry the calibrator fitted to its own scores.
    if not (args.out / "calibration.json").is_file():
        raise RuntimeError("trained scorer did not produce calibration.json")
    (args.out / "metrics.json").write_text(json.dumps(metrics, indent=2) + "\n", encoding="utf-8")
    print(f"saved artifacts under {args.out}")


if __name__ == "__main__":
    main()
