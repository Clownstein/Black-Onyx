from __future__ import annotations

from inference_worker.adapters import (
    adapt_code_features,
    adapt_host_state_features,
    adapt_log_features,
    adapt_metrics_features,
    adapt_network_features,
    direct_predict_body,
)


def test_adapt_log_features_extracts_template_ids() -> None:
    msg = {
        "tenant_id": "tenant-a",
        "asset_id": "host-1",
        "service_id": "payments-api",
        "sequence_id": "seq-1",
        "feature_version": "1.0",
        "window_start": "2026-07-26T12:00:00Z",
        "window_end": "2026-07-26T12:05:00Z",
        "events": [
            {"event_id": "e1", "template_id": "tpl-auth-success", "severity": "INFO"},
            {"event_id": "e2", "template_id": "tpl-auth-failure", "severity": "WARN"},
        ],
    }
    body = adapt_log_features(msg)
    assert body["model_name"] == "log-model"
    assert body["tenant_id"] == "tenant-a"
    assert body["request_id"] == "seq-1"
    assert body["items"][0]["template_ids"] == ["tpl-auth-success", "tpl-auth-failure"]
    assert body["features"]["asset_id"] == "host-1"
    assert body["features"]["service_id"] == "payments-api"
    assert body["model_request"]["items"][0]["events"][0]["template_id"] == "tpl-auth-success"
    direct = direct_predict_body(body)
    assert direct["items"][0]["events"][1]["template_id"] == "tpl-auth-failure"


def test_adapt_log_features_synthesizes_when_empty() -> None:
    body = adapt_log_features({"tenant_id": "t1"})
    assert body["items"][0]["events"][0]["template_id"] == "[UNK]"
    assert body["features"]["asset_id"] == "unknown"


def test_adapt_network_features_from_window() -> None:
    msg = {
        "tenant_id": "tenant-a",
        "asset_id": "host-1",
        "window_start": "2026-07-26T12:00:00Z",
        "window_end": "2026-07-26T12:05:00Z",
        "flows": [{"peer_hash": "abc", "dst_port": 443, "bytes": 10}],
        "detections": [{"type": "new_external_peer", "score": 0.9}],
        "aggregates": {"distinct_peers": 1, "failed_connections": 0},
    }
    body = adapt_network_features(msg)
    assert body["model_name"] == "network-model"
    assert body["features"]["flows"][0]["dst_port"] == 443
    assert body["model_request"]["detections"][0]["type"] == "new_external_peer"
    assert body["model_request"]["aggregates"]["distinct_peers"] == 1


def test_adapt_network_features_uses_flow_sample() -> None:
    body = adapt_network_features(
        {
            "tenant_id": "t1",
            "asset_id": "a1",
            "flow_sample": [{"peer_hash": "x"}],
        }
    )
    assert len(body["model_request"]["flows"]) == 1


def test_adapt_metrics_features_values_dict() -> None:
    msg = {
        "tenant_id": "tenant-a",
        "asset_id": "svc-1",
        "profile": "web_service_v1",
        "missing_fraction": 0.01,
        "values": {"cpu": [0.1, 0.2], "mem": [0.5, 0.6]},
        "missingness": {"cpu": [0.0, 0.0], "mem": [0.0, 0.0]},
    }
    body = adapt_metrics_features(msg)
    assert body["model_name"] == "metrics-model"
    assert body["model_request"]["values"]["cpu"] == [0.1, 0.2]
    assert body["model_request"]["profile"] == "web_service_v1"


def test_adapt_metrics_features_2d_array() -> None:
    body = adapt_metrics_features(
        {
            "tenant_id": "t1",
            "values": [[1.0, 2.0], [3.0, 4.0]],
        }
    )
    assert "m0" in body["model_request"]["values"]
    assert body["model_request"]["values"]["m0"] == [1.0, 2.0]


def test_adapt_code_features() -> None:
    msg = {
        "tenant_id": "tenant-a",
        "asset_id": "repo-1",
        "path": "app/auth.py",
        "language": "python",
        "diff_text": "@@ -1 +1 @@\n+password = 'secret'\n",
        "scanner_findings": [{"check_id": "hardcoded-secret", "message": "secret"}],
        "files_changed": ["app/auth.py"],
        "diff_stats": {"added_lines": 1, "removed_lines": 0},
    }
    body = adapt_code_features(msg)
    assert body["model_name"] == "code-model"
    assert "password" in body["model_request"]["diff_text"]
    assert body["model_request"]["path"] == "app/auth.py"
    assert body["model_request"]["language"] == "python"
    assert body["model_request"]["scanner_findings"][0]["check_id"] == "hardcoded-secret"


def test_adapt_host_state_features_builds_items() -> None:
    msg = {
        "tenant_id": "tenant-a",
        "asset_id": "host-1",
        "service_id": "ssh",
        "feature_version": "host-state.features.v1",
        "window_start": "2026-07-26T12:00:00Z",
        "window_end": "2026-07-26T12:05:00Z",
        "detections": [{"detector": "new_listening_port", "score": 0.7}],
        "process_events": [{"process": {"name": "sshd"}}],
        "event_count": 1,
    }
    body = adapt_host_state_features(msg)
    assert body["model_name"] == "host-state-model"
    assert body["tenant_id"] == "tenant-a"
    assert body["items"][0]["asset_id"] == "host-1"
    assert body["items"][0]["detections"][0]["detector"] == "new_listening_port"
    direct = direct_predict_body(body)
    assert direct["items"][0]["rule_hits"][0]["detector"] == "new_listening_port"
