from __future__ import annotations

from black_onyx_contracts import Finding

from inference_worker.findings import build_finding, normalize_code_finding


def test_build_finding_from_log_predict() -> None:
    feature_msg = {
        "tenant_id": "tenant-a",
        "asset_id": "host-1",
        "service_id": "payments-api",
        "feature_version": "1.0",
        "window_start": "2026-07-26T12:00:00+00:00",
        "window_end": "2026-07-26T12:05:00+00:00",
        "event_type": "log.feature_sequence",
    }
    predict_response = {
        "model_name": "log-transformer",
        "model_version": "0.1.0",
        "results": [
            {
                "raw_score": 1.2,
                "calibrated_score": 0.77,
                "top_contributors": [
                    {
                        "type": "unexpected_template",
                        "contribution": 0.9,
                        "observed_template": "tpl-privilege-change",
                        "position": 2,
                    }
                ],
            }
        ],
    }
    finding = build_finding("log-model", feature_msg, predict_response)
    validated = Finding.model_validate(finding)
    assert validated.finding_type == "log_anomaly"
    assert validated.calibrated_score == 0.77
    assert validated.asset_id == "host-1"
    assert validated.service_id == "payments-api"
    assert validated.fingerprint
    assert validated.contributors
    assert validated.contributors[0].template_id == "tpl-privilege-change"  # type: ignore[union-attr]


def test_build_finding_from_risk_score() -> None:
    feature_msg = {
        "tenant_id": "tenant-a",
        "asset_id": "host-1",
        "window_start": "2026-07-26T12:00:00Z",
        "window_end": "2026-07-26T12:05:00Z",
    }
    predict_response = {
        "risk_score": 0.91,
        "severity": "high",
        "model_version": "1.4.0",
        "contributors": [{"type": "new_external_peer", "contribution": 0.8, "summary": "peer"}],
    }
    finding = build_finding("network-model", feature_msg, predict_response)
    assert finding["finding_type"] == "network_anomaly"
    assert finding["calibrated_score"] == 0.91
    assert finding["severity_hint"] == "high"
    Finding.model_validate(finding)


def test_fingerprint_stable_for_same_inputs() -> None:
    feature_msg = {"tenant_id": "t1", "asset_id": "a1"}
    response = {
        "calibrated_score": 0.5,
        "model_version": "1",
        "contributors": [{"type": "x", "contribution": 1.0, "template_id": "tpl-1"}],
    }
    a = build_finding("log-model", feature_msg, response)
    b = build_finding("log-model", feature_msg, response)
    assert a["fingerprint"] == b["fingerprint"]
    assert a["finding_id"] != b["finding_id"]


def test_normalize_code_finding() -> None:
    msg = {
        "event_type": "code.findings",
        "tenant_id": "tenant-a",
        "asset_id": "repo-1",
        "advisory_only": True,
        "scanner_findings": [
            {"check_id": "hardcoded-secret", "message": "secret in source", "score": 0.8}
        ],
        "scanners": {"semgrep": {"ok": True}},
        "risk_score": 0.65,
    }
    finding = normalize_code_finding(msg)
    validated = Finding.model_validate(finding)
    assert validated.finding_type == "code_risk"
    assert validated.calibrated_score == 0.65
    assert finding["context"]["normalized_from"] == "code.findings"
    assert finding["context"]["advisory_only"] is True
