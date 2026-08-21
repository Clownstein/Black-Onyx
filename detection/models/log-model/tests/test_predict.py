from pathlib import Path

from fastapi.testclient import TestClient
from inference.app import app
from log_model.scorer import LogAnomalyScorer
from log_model.vocab import TemplateVocab
from training.train import SeqDataset, load_dataset

EXAMPLE_DATASET = Path(__file__).resolve().parents[1] / "training" / "examples" / "platform_sequences.jsonl"


def test_platform_dataset_preserves_templates_and_severity():
    vocab = TemplateVocab()
    rows = load_dataset(EXAMPLE_DATASET, vocab)
    assert len(rows) >= 8
    assert {row["label"] for row in rows} == {0, 1}
    assert rows[1]["templates"][-1] == "tpl-shell-exec"
    encoded = SeqDataset(rows, vocab, max_len=8)[1]
    assert encoded["attention_mask"].sum().item() == 4
    assert encoded["severity_ids"][3].item() != 0


def test_predict_shape_and_contributors() -> None:
    scorer = LogAnomalyScorer(artifacts_dir=Path("/nonexistent-artifacts"))
    batch = {
        "request_id": "req-1",
        "tenant_id": "tenant-a",
        "model_name": "log-transformer",
        "feature_version": "1.0",
        "items": [
            {
                "sequence_id": "seq-1",
                "events": [
                    {"template_id": "tpl-auth-success", "severity": "INFO"},
                    {"template_id": "tpl-auth-failure", "severity": "WARN"},
                    {"template_id": "tpl-privilege-change", "severity": "ERROR"},
                    {"template_id": "tpl-session-create", "severity": "INFO"},
                ],
            }
        ],
    }
    out = scorer.predict(batch)
    assert out["model_version"]
    assert len(out["results"]) == 1
    result = out["results"][0]
    assert "calibrated_score" in result
    assert "raw_score" in result
    assert "top_contributors" in result
    assert len(result["top_contributors"]) >= 1
    assert "observed_template" in result["top_contributors"][0]


def test_fastapi_predict_endpoint() -> None:
    client = TestClient(app)
    resp = client.post(
        "/v1/predict",
        json={
            "request_id": "req-2",
            "tenant_id": "tenant-a",
            "model_name": "log-transformer",
            "feature_version": "1.0",
            "items": [
                {
                    "sequence_id": "seq-2",
                    "sequence": [
                        {"template_id": "tpl-auth-success", "severity": "INFO"},
                        {"template_id": "tpl-db-query", "severity": "INFO"},
                        {"template_id": "tpl-http-200", "severity": "INFO"},
                        {"template_id": "tpl-cache-hit", "severity": "INFO"},
                    ],
                }
            ],
        },
    )
    if app.version and LogAnomalyScorer().health()["status"] == "ready":
        assert resp.status_code == 200
        body = resp.json()
        assert body["results"][0]["top_contributors"]
        assert 0.0 <= body["results"][0]["calibrated_score"] <= 1.0
    else:
        assert resp.status_code == 503
        assert "trained log model artifact" in resp.json()["detail"]
