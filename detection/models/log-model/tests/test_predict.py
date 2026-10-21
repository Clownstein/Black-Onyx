from pathlib import Path

from fastapi.testclient import TestClient
from inference.app import app
from log_model.scorer import LogAnomalyScorer
from log_model.vocab import TemplateVocab
from training.train import SeqDataset, evaluate_scores, load_dataset, split_rows

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


def test_reviewed_splits_and_metrics_are_held_out():
    vocab = TemplateVocab()
    rows = load_dataset(EXAMPLE_DATASET, vocab, add_to_vocab=False)
    partitions = split_rows(rows)
    assert {name: len(value) for name, value in partitions.items()} == {
        "train": 4, "validation": 2, "test": 2,
    }
    assert len(vocab.token_to_id) == 5
    for row in partitions["train"]:
        for template in row["templates"]:
            vocab.add(template)
    assert vocab.encode("tpl-session-refresh") == vocab.unk_id
    metrics = evaluate_scores([0.1, 0.9], [0, 1], split="test")
    assert (metrics["tp"], metrics["tn"], metrics["f1"]) == (1, 1, 1.0)
    assert metrics["brier_score"] > 0


def test_reviewed_split_rejects_entity_leakage():
    vocab = TemplateVocab()
    rows = load_dataset(EXAMPLE_DATASET, vocab)
    rows[2]["asset_id"] = rows[0]["asset_id"]
    rows[2]["service_id"] = rows[0]["service_id"]
    import pytest

    with pytest.raises(ValueError, match="crosses dataset splits"):
        split_rows(rows)


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
