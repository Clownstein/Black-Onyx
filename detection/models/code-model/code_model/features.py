from __future__ import annotations

import math
import re
from typing import Any

import numpy as np

FEATURE_NAMES = [
    "has_shell_true",
    "has_eval",
    "secret_like",
    "change_size_log",
    "semgrep_high",
    "auth_path",
]

_SECRET_RE = re.compile(
    r"(password\s*=|api[_-]?key|secret\s*=|BEGIN (RSA |OPENSSH )?PRIVATE KEY|AKIA[0-9A-Z]{16})",
    re.IGNORECASE,
)
_AUTH_PATH_RE = re.compile(r"(^|/)(auth|login|session|oauth|iam|permission)s?(/|\.|$)", re.I)


def extract_feature_flags(payload: dict[str, Any]) -> dict[str, float]:
    text = str(
        payload.get("diff_text")
        or (payload.get("text_features") or {}).get("diff_text")
        or payload.get("diff")
        or ""
    )
    files = [str(f) for f in (payload.get("files_changed") or [])]
    scanner_findings = payload.get("scanner_findings") or []
    added = float((payload.get("diff_stats") or {}).get("added_lines") or text.count("\n") or 0)
    removed = float((payload.get("diff_stats") or {}).get("removed_lines") or 0)
    change_size = max(0.0, added + removed)

    has_shell = 1.0 if re.search(r"shell\s*=\s*True", text) else 0.0
    has_eval = 1.0 if re.search(r"\beval\s*\(", text) else 0.0
    secret_like = 1.0 if _SECRET_RE.search(text) else 0.0
    change_size_log = float(math.log1p(change_size))
    semgrep_high = 1.0 if any(
        str(f.get("severity", "")).lower() in {"high", "error", "critical"}
        or "high" in str(f.get("rule_id", "")).lower()
        for f in scanner_findings
    ) else 0.0
    auth_path = 1.0 if any(_AUTH_PATH_RE.search(f) for f in files) or "auth" in text.lower() else 0.0

    return {
        "has_shell_true": has_shell,
        "has_eval": has_eval,
        "secret_like": secret_like,
        "change_size_log": change_size_log,
        "semgrep_high": semgrep_high,
        "auth_path": auth_path,
    }


def feature_vector(payload: dict[str, Any]) -> np.ndarray:
    flags = extract_feature_flags(payload)
    return np.asarray([flags[name] for name in FEATURE_NAMES], dtype=np.float64)


def build_evidence(payload: dict[str, Any]) -> list[dict[str, Any]]:
    text = str(
        payload.get("diff_text")
        or (payload.get("text_features") or {}).get("diff_text")
        or payload.get("diff")
        or ""
    )
    files = payload.get("files_changed") or ["unknown"]
    file0 = str(files[0]) if files else "unknown"
    evidence: list[dict[str, Any]] = []

    patterns = [
        (r"shell\s*=\s*True", "shell=True execution"),
        (r"\beval\s*\(", "eval() usage"),
        (r"pickle\.loads\s*\(", "pickle.loads deserialization"),
        (
            r"(password\s*=|api[_-]?key|secret\s*=)",
            "secret-like literal",
        ),
    ]
    for pattern, summary in patterns:
        for match in re.finditer(pattern, text, flags=re.IGNORECASE):
            line = text[: match.start()].count("\n") + 1
            evidence.append(
                {
                    "file": file0,
                    "start_line": line,
                    "end_line": line,
                    "summary": summary,
                }
            )

    for finding in payload.get("scanner_findings") or []:
        start = int(finding.get("start_line") or 1)
        end = int(finding.get("end_line") or start)
        evidence.append(
            {
                "file": str(finding.get("path") or file0),
                "start_line": start,
                "end_line": end,
                "summary": str(finding.get("message") or finding.get("rule_id") or "scanner finding"),
            }
        )
    return evidence[:50]


def risk_categories(flags: dict[str, float]) -> list[str]:
    cats: list[str] = []
    if flags["has_shell_true"] or flags["has_eval"]:
        cats.append("dangerous_exec")
    if flags["secret_like"]:
        cats.append("credential_exposure")
    if flags["semgrep_high"]:
        cats.append("scanner_high")
    if flags["auth_path"]:
        cats.append("auth_path_change")
    if not cats:
        cats.append("benign_change")
    return cats


# Backward-compatible alias used by older scorer paths.
def extract_text_features(payload: dict[str, Any]) -> dict[str, Any]:
    flags = extract_feature_flags(payload)
    return {
        "vector": feature_vector(payload),
        "categories": risk_categories(flags),
        "evidence": build_evidence(payload),
        "flags": flags,
    }
