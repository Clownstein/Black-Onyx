from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
CODE_MODEL = ROOT / "models" / "code-model"
if str(CODE_MODEL) not in sys.path:
    sys.path.insert(0, str(CODE_MODEL))

from code_model.scorer import ChangeRiskModel  # noqa: E402
from training.train import synthetic_dataset  # noqa: E402


def test_risky_diff_scores_higher_than_safe() -> None:
    samples, labels = synthetic_dataset()
    model = ChangeRiskModel()
    model.fit(samples, labels)

    risky = {
        "diff_text": "+eval(user_input)\n+subprocess.call(cmd, shell=True)\n+password='x'\n",
        "files_changed": ["auth/session.py"],
        "diff_stats": {"added_lines": 3, "removed_lines": 0},
        "scanner_findings": [
            {
                "severity": "high",
                "path": "auth/session.py",
                "start_line": 1,
                "end_line": 2,
                "message": "dangerous patterns",
            }
        ],
    }
    safe = {
        "diff_text": "+def add(a, b):\n+    return a + b\n",
        "files_changed": ["math_utils.py"],
        "diff_stats": {"added_lines": 2, "removed_lines": 0},
        "scanner_findings": [],
    }

    risky_score = model.predict(risky)["risk_score"]
    safe_score = model.predict(safe)["risk_score"]
    assert risky_score > safe_score
