from pathlib import Path

from code_model.scorer import ChangeRiskModel
from fastapi.testclient import TestClient
from inference.app import app
from training.train import load_dataset, synthetic_dataset

EXAMPLE_DATASET = Path(__file__).resolve().parents[1] / "training" / "examples" / "platform_changes.jsonl"


def test_platform_dataset_loads_both_classes():
    samples, labels = load_dataset(EXAMPLE_DATASET)
    assert len(samples) >= 8
    assert set(labels) == {0, 1}
    assert samples[0]["files_changed"] == ["src/cart.py"]
    assert samples[1]["scanner_findings"][0]["cwe_ids"] == ["CWE-78"]


def test_train_and_predict_fields(tmp_path: Path):
    samples, labels = synthetic_dataset()
    model = ChangeRiskModel()
    model.fit(samples, labels)
    model.save(tmp_path)
    assert (tmp_path / "model.joblib").is_file()
    assert (tmp_path / "config.json").is_file()
    assert (tmp_path / "thresholds.json").is_file()

    loaded = ChangeRiskModel()
    loaded.load(tmp_path)
    risky = samples[0]
    safe = samples[-1]
    risky_score = loaded.predict(risky)["risk_score"]
    safe_score = loaded.predict(safe)["risk_score"]
    assert risky_score > safe_score

    result = loaded.predict(risky)
    assert "risk_score" in result
    assert "risk_categories" in result
    assert isinstance(result["evidence"], list)
    assert result["evidence"]
    assert {"file", "start_line", "end_line", "summary"} <= set(result["evidence"][0])
    assert result["meta"]["advisory_only"] is True


def test_predict_endpoint_fails_closed_without_trained_artifact():
    client = TestClient(app)
    resp = client.post(
        "/v1/predict",
        json={
            "diff_text": "+eval(x)\n+subprocess.call(c, shell=True)\n",
            "files_changed": ["auth/login.py"],
            "diff_stats": {"added_lines": 2},
            "scanner_findings": [
                {
                    "severity": "high",
                    "path": "auth/login.py",
                    "start_line": 1,
                    "end_line": 1,
                    "message": "dangerous call",
                }
            ],
        },
    )
    assert resp.status_code == 503
    body = resp.json()
    assert body["detail"] == "A trained code model artifact is required"
