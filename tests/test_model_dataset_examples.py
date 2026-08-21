from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def test_non_training_model_examples_are_explicit_about_boundaries() -> None:
    host_rows = _jsonl(ROOT / "detection/models/host-state-model/examples/platform_requests.jsonl")
    assert all(row["model_name"] == "host-state-model" for row in host_rows)
    assert all(row["items"] for row in host_rows)

    antares_rows = _jsonl(ROOT / "detection/models/antares-1b/examples/platform_localization_tasks.jsonl")
    assert all(row["cwe_id"].startswith("CWE-") for row in antares_rows)
    assert all(row["ground_truth_files"] for row in antares_rows)
    assert all(row["human_review_required"] is True for row in antares_rows)
    assert {row["split"] for row in antares_rows} == {"validation", "test"}


def test_training_examples_cover_both_labels_and_all_splits() -> None:
    paths = (
        ROOT / "detection/models/log-model/training/examples/platform_sequences.jsonl",
        ROOT / "detection/models/network-model/training/examples/platform_windows.jsonl",
        ROOT / "detection/models/metrics-model/training/examples/platform_windows.jsonl",
        ROOT / "detection/models/code-model/training/examples/platform_changes.jsonl",
    )
    for path in paths:
        rows = _jsonl(path)
        assert len(rows) >= 8
        assert {row["label"] for row in rows} == {0, 1}
        assert {row["split"] for row in rows} == {"train", "validation", "test"}


def test_detailed_rows_retain_processor_context_and_safe_identifiers() -> None:
    log_rows = _jsonl(ROOT / "detection/models/log-model/training/examples/platform_sequences.jsonl")
    detailed_log = next(row for row in log_rows if row["sample_id"] == "log-anomaly-004")
    assert detailed_log["event_type"] == "log.feature_sequence"
    assert detailed_log["processor_version"]
    assert detailed_log["events"][0]["occurred_at"]
    assert detailed_log["annotation"]["mitre_techniques"]

    network_rows = _jsonl(ROOT / "detection/models/network-model/training/examples/platform_windows.jsonl")
    detailed_network = next(row for row in network_rows if row["sample_id"] == "network-anomaly-004")
    assert detailed_network["event_count"] == len(detailed_network["flows"])
    assert detailed_network["detections"][0]["evidence"]
    assert all("src_ip" not in flow and "dst_ip" not in flow for flow in detailed_network["flows"])
    assert all(len(flow["peer_hash"]) >= 16 for flow in detailed_network["flows"])

    metrics_rows = _jsonl(ROOT / "detection/models/metrics-model/training/examples/platform_windows.jsonl")
    detailed_metrics = next(row for row in metrics_rows if row["sample_id"] == "metrics-anomaly-004")
    assert detailed_metrics["time_features"] == {"hour_of_day": 16, "day_of_week": 1}
    assert detailed_metrics["annotation"]["review_status"] == "confirmed_service_degradation"

    code_rows = _jsonl(ROOT / "detection/models/code-model/training/examples/platform_changes.jsonl")
    detailed_code = next(row for row in code_rows if row["sample_id"] == "code-risk-004")
    assert detailed_code["commit"]["change_id"]
    assert detailed_code["scanner_summary"]["codeql"]["status"] == "ready"
    assert detailed_code["scanner_findings"][0]["cwe_ids"] == ["CWE-98"]


def test_dataset_guide_links_every_model_surface() -> None:
    guide = (ROOT / "detection/models/datasets/README.md").read_text(encoding="utf-8")
    for model in (
        "log-model",
        "network-model",
        "metrics-model",
        "code-model",
        "host-state-model",
        "malware-static",
        "antares-1b",
    ):
        assert model in guide
