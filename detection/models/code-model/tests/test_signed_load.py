import json
from pathlib import Path

import pytest
import joblib

from black_onyx_model_package import build_model_package
from code_model.scorer import ChangeRiskModel


def _package(tmp_path: Path, *, model_name: str = "code-model", calibration: dict | None = None) -> Path:
    source = tmp_path / "source.joblib"
    joblib.dump({"model": object()}, source)
    return build_model_package(
        tmp_path / "output",
        model_name=model_name,
        version="v1",
        dataset_manifest={"feature_schema": {"features": []}},
        signing_key="test-signing-key",
        metrics={},
        thresholds={},
        config={"model_name": model_name},
        calibration=calibration or {},
        model_source=source,
    )


@pytest.mark.parametrize("mutation", ["unsigned", "tampered", "extra", "wrong_key", "wrong_model", "wrong_key_id"])
def test_rejects_invalid_package_before_deserializing(tmp_path: Path, monkeypatch, mutation: str) -> None:
    package = _package(tmp_path, model_name="metrics-model" if mutation == "wrong_model" else "code-model")
    key = "test-signing-key"
    if mutation == "unsigned":
        (package / "signature.json").unlink()
    elif mutation == "tampered":
        (package / "model.joblib").write_bytes(b"modified")
    elif mutation == "extra":
        (package / "untracked.joblib").write_bytes(b"other")
    elif mutation == "wrong_key":
        key = "wrong-key"
    elif mutation == "wrong_key_id":
        signature = json.loads((package / "signature.json").read_text(encoding="utf-8"))
        signature["key_id"] = "unknown-key"
        (package / "signature.json").write_text(json.dumps(signature), encoding="utf-8")

    def forbidden_load(*_args, **_kwargs):
        raise AssertionError("Unverified joblib was deserialized")

    monkeypatch.setattr("code_model.scorer.joblib.load", forbidden_load)
    with pytest.raises(ValueError):
        ChangeRiskModel().load(package, signing_key=key)


def test_rejects_missing_signing_key_before_deserializing(tmp_path: Path, monkeypatch) -> None:
    package = _package(tmp_path)
    monkeypatch.setattr("code_model.scorer.joblib.load", lambda *_args, **_kwargs: pytest.fail("joblib called"))
    with pytest.raises(ValueError, match="signing key"):
        ChangeRiskModel().load(package, signing_key="")


def test_failed_metadata_load_does_not_leave_model_ready(tmp_path: Path) -> None:
    package = _package(tmp_path, calibration={"scale": "bad"})
    model = ChangeRiskModel()
    with pytest.raises(ValueError):
        model.load(package, signing_key="test-signing-key")
    assert model.model is None


def test_model_is_loaded_from_verified_private_snapshot(tmp_path: Path, monkeypatch) -> None:
    package = _package(tmp_path)
    seen: list[Path] = []

    def load_from_snapshot(path: Path):
        seen.append(path)
        (package / "model.joblib").write_bytes(b"mutated after snapshot")
        return {"model": object()}

    monkeypatch.setattr("code_model.scorer.joblib.load", load_from_snapshot)
    ChangeRiskModel().load(package, signing_key="test-signing-key")
    assert len(seen) == 1
    assert seen[0] != package / "model.joblib"
    assert "black-onyx-model-" in str(seen[0])
