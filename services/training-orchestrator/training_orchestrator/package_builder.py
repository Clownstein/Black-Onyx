"""Model package builder matching platform §13.4 layout."""

from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path
from typing import Any

WEIGHT_NAMES = ("model.onnx", "model.joblib")

PACKAGE_META_FILES = (
    "model-card.md",
    "config.json",
    "tokenizer-or-feature-schema.json",
    "calibration.json",
    "thresholds.json",
    "metrics.json",
    "dataset-manifest.json",
    "signature.json",
    "checksums.txt",
)

# Back-compat: tests assert every name in PACKAGE_FILES exists for ONNX packages.
PACKAGE_FILES = ("model.onnx",) + PACKAGE_META_FILES


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _write_json(path: Path, payload: dict[str, Any] | list[Any]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def build_model_package(
    output_dir: Path,
    *,
    model_name: str,
    version: str,
    dataset_manifest: dict[str, Any],
    signing_key: str,
    metrics: dict[str, Any],
    thresholds: dict[str, Any],
    config: dict[str, Any],
    calibration: dict[str, Any],
    model_source: Path | None = None,
    onnx_source: Path | None = None,
) -> Path:
    """Build a signed model package.

    Prefer ``model_source`` (``.onnx`` or ``.joblib``). ``onnx_source`` is kept for
    callers that still pass the older keyword.
    """
    package_dir = output_dir / "model-package"
    package_dir.mkdir(parents=True, exist_ok=True)

    source = model_source or onnx_source
    if source is None or not source.is_file() or source.stat().st_size == 0:
        raise ValueError("A non-empty trained model artifact (ONNX or joblib) is required")

    suffix = source.suffix.lower()
    if suffix == ".onnx":
        weight_name = "model.onnx"
    elif suffix == ".joblib":
        weight_name = "model.joblib"
    else:
        raise ValueError(f"unsupported model artifact type: {source.name}")

    weight_path = package_dir / weight_name
    weight_path.write_bytes(source.read_bytes())

    model_card = (
        f"# Model card: {model_name} {version}\n\n"
        "## Intended use\nAnomaly scoring for platform inference.\n\n"
        "## Prohibited use\nDo not use for autonomous destructive actions.\n\n"
        "## Supported data sources\nPlatform normalized events for this modality.\n\n"
        f"## Training period\n{dataset_manifest.get('time_range', {})}\n\n"
        "## Evaluation summary\nSee metrics.json.\n\n"
        "## Known limitations\nReview the supplied training metrics and dataset manifest.\n\n"
        "## Sensitive-data considerations\nMask PII before scoring.\n\n"
        "## Expected drift patterns\nTemplate and score distribution shifts.\n\n"
        "## Threshold rationale\nSee thresholds.json.\n\n"
        "## Rollback version\nPrevious champion alias.\n\n"
        "## Owner\nmlops\n\n"
        "## Approval history\nCandidate promotion via training-orchestrator.\n"
    )
    (package_dir / "model-card.md").write_text(model_card, encoding="utf-8")

    _write_json(package_dir / "config.json", config)
    _write_json(
        package_dir / "tokenizer-or-feature-schema.json",
        {
            "schema_version": dataset_manifest.get("schema_version", "1.2"),
            "features": ["template_id", "severity_hash", "sequence_position"],
        },
    )
    _write_json(package_dir / "calibration.json", calibration)
    _write_json(package_dir / "thresholds.json", thresholds)
    _write_json(package_dir / "metrics.json", metrics)
    _write_json(package_dir / "dataset-manifest.json", dataset_manifest)

    package_names = (weight_name,) + PACKAGE_META_FILES
    checksum_lines: list[str] = []
    checksum_map: dict[str, str] = {}
    for name in package_names:
        if name in {"signature.json", "checksums.txt"}:
            continue
        path = package_dir / name
        digest = _sha256_hex(path.read_bytes())
        checksum_map[name] = digest
        checksum_lines.append(f"{digest}  {name}")

    checksums_text = "\n".join(checksum_lines) + "\n"
    (package_dir / "checksums.txt").write_text(checksums_text, encoding="utf-8")
    checksum_map["checksums.txt"] = _sha256_hex(checksums_text.encode("utf-8"))

    canonical = json.dumps(checksum_map, sort_keys=True, separators=(",", ":")).encode("utf-8")
    signature = hmac.new(signing_key.encode("utf-8"), canonical, hashlib.sha256).hexdigest()
    _write_json(
        package_dir / "signature.json",
        {
            "alg": "HMAC-SHA256",
            "key_id": "artifact-signing-key",
            "checksums": checksum_map,
            "signature": signature,
        },
    )
    return package_dir
