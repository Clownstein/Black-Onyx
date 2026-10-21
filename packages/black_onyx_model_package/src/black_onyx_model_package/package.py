"""Model package builder for the platform's signed model-package layout."""

from __future__ import annotations

import hashlib
import hmac
import json
import shutil
from pathlib import Path
from typing import Any

WEIGHT_NAMES = ("model.onnx", "model.joblib")
LOG_MODEL_NAMES = frozenset({"log-model", "log", "log-transformer"})
MODEL_ALIASES = {
    "log": "log-model",
    "log-transformer": "log-model",
    "network": "network-model",
    "metrics": "metrics-model",
    "code": "code-model",
}

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


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


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
    vocab_source: Path | None = None,
) -> Path:
    """Build a signed model package.

    Prefer ``model_source`` (``.onnx`` or ``.joblib``). ``onnx_source`` is kept for
    callers that still pass the older keyword.
    """
    if not signing_key.strip():
        raise ValueError("Model artifact signing key is required")
    configured_name = config.get("model_name")
    canonical_name = MODEL_ALIASES.get(model_name, model_name)
    if MODEL_ALIASES.get(configured_name, configured_name) != canonical_name:
        raise ValueError("Model package config must match the model identity")
    package_dir = output_dir / "model-package"
    package_dir.mkdir(parents=True, exist_ok=True)
    if any(package_dir.iterdir()):
        raise ValueError("Model package output directory is not empty")

    if model_name in LOG_MODEL_NAMES:
        if vocab_source is None or not vocab_source.is_file() or vocab_source.stat().st_size == 0:
            raise ValueError("Log model requires a non-empty trained vocab.json")
        try:
            vocab = json.loads(vocab_source.read_text(encoding="utf-8"))
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            raise ValueError("Log model vocabulary is invalid") from exc
        if not isinstance(vocab, dict) or not all(
            isinstance(token, str) and isinstance(index, int) and index >= 0
            for token, index in vocab.items()
        ) or not {"[PAD]", "[CLS]", "[SEP]", "[MASK]", "[UNK]"}.issubset(vocab):
            raise ValueError("Log model vocabulary is invalid")
        shutil.copyfile(vocab_source, package_dir / "vocab.json")
    elif vocab_source is not None:
        raise ValueError("Only log model packages may include vocab.json")

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
    shutil.copyfile(source, weight_path)

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

    package_config = dict(config)
    package_config["model_name"] = canonical_name
    if package_config.get("model_version") != version and package_config.get("model_version"):
        package_config.setdefault("trainer_model_version", package_config["model_version"])
    package_config["model_version"] = version
    _write_json(package_dir / "config.json", package_config)
    feature_schema = dataset_manifest.get("feature_schema")
    if not isinstance(feature_schema, dict):
        feature_schema = {"features": [], "source": "synthetic_demo_unverified"}
    _write_json(package_dir / "tokenizer-or-feature-schema.json", {
        "schema_version": dataset_manifest.get("schema_version", "1.2"),
        **feature_schema,
    })
    _write_json(package_dir / "calibration.json", calibration)
    _write_json(package_dir / "thresholds.json", thresholds)
    _write_json(package_dir / "metrics.json", metrics)
    _write_json(package_dir / "dataset-manifest.json", dataset_manifest)

    package_names = (weight_name,) + PACKAGE_META_FILES
    if model_name in LOG_MODEL_NAMES:
        package_names += ("vocab.json",)
    checksum_lines: list[str] = []
    checksum_map: dict[str, str] = {}
    for name in package_names:
        if name in {"signature.json", "checksums.txt"}:
            continue
        path = package_dir / name
        digest = _sha256_file(path)
        checksum_map[name] = digest
        checksum_lines.append(f"{digest}  {name}")

    checksums_text = "\n".join(checksum_lines) + "\n"
    (package_dir / "checksums.txt").write_text(checksums_text, encoding="utf-8")
    checksum_map["checksums.txt"] = _sha256_file(package_dir / "checksums.txt")

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


def verify_model_package(
    package_dir: Path,
    signing_key: str,
    *,
    expected_model_name: str | None = None,
    expected_weight: str | None = None,
) -> str:
    """Verify the signed inventory and return the single model weight name."""
    if not signing_key.strip():
        raise ValueError("Model artifact signing key is required")
    if not package_dir.is_dir() or package_dir.is_symlink() or (package_dir / "signature.json").is_symlink():
        raise ValueError("Model package signature is unavailable")
    try:
        signed = json.loads((package_dir / "signature.json").read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise ValueError("Model package signature is unavailable") from exc
    if not isinstance(signed, dict):
        raise ValueError("Invalid model package signature")
    checksums = signed.get("checksums")
    if signed.get("alg") != "HMAC-SHA256" or signed.get("key_id") != "artifact-signing-key" or not isinstance(checksums, dict):
        raise ValueError("Invalid model package signature")
    weights = set(checksums) & set(WEIGHT_NAMES)
    expected = set(PACKAGE_META_FILES) - {"signature.json"}
    inventory = set(checksums)
    if len(weights) != 1 or inventory not in (expected | weights, expected | weights | {"vocab.json"}):
        raise ValueError("Invalid model package inventory")
    if {path.name for path in package_dir.iterdir()} != inventory | {"signature.json"}:
        raise ValueError("Model package contains unsigned files")
    for name, digest in checksums.items():
        if not isinstance(digest, str) or len(digest) != 64:
            raise ValueError("Invalid model package checksum")
        path = package_dir / name
        if path.is_symlink() or not path.is_file() or not hmac.compare_digest(_sha256_file(path), digest):
            raise ValueError(f"Model package file failed verification: {name}")
    canonical = json.dumps(checksums, sort_keys=True, separators=(",", ":")).encode("utf-8")
    expected_sig = hmac.new(signing_key.encode("utf-8"), canonical, hashlib.sha256).hexdigest()
    if not isinstance(signed.get("signature"), str) or not hmac.compare_digest(
        signed["signature"], expected_sig,
    ):
        raise ValueError("Model package signature mismatch")
    config = json.loads((package_dir / "config.json").read_text(encoding="utf-8"))
    if not isinstance(config, dict):
        raise ValueError("Model package config is invalid")
    model_name = config.get("model_name")
    if model_name in LOG_MODEL_NAMES and "vocab.json" not in inventory:
        raise ValueError("Log model package is missing signed vocab.json")
    if model_name not in LOG_MODEL_NAMES and "vocab.json" in inventory:
        raise ValueError("Non-log model package contains vocab.json")
    weight = next(iter(weights))
    if expected_model_name is not None and model_name != expected_model_name:
        raise ValueError("Model package identity mismatch")
    if expected_weight is not None and weight != expected_weight:
        raise ValueError("Model package weight mismatch")
    return weight
