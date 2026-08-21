from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from black_onyx_calibration import fit_platt, save_calibrator
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
    args = parser.parse_args()

    samples, labels = load_dataset(args.dataset) if args.dataset else synthetic_dataset()
    model = ChangeRiskModel()
    model.fit(samples, labels)
    model.save(args.out)
    # Ensure calibrator sidecar exists even if fit path skipped encoder calibrator write
    if not (args.out / "calibration.json").is_file():
        save_calibrator(fit_platt([0.1, 0.9], [0, 1]), args.out / "calibration.json")
    print(f"saved artifacts under {args.out}")


if __name__ == "__main__":
    main()
