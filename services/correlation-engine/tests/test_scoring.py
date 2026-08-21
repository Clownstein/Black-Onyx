from correlation_engine.scoring import (
    FindingView,
    apply_deterministic_rules,
    build_incident_payload,
    feature_vector,
    incident_risk,
)


def test_simple_logistic_increases_with_log_score() -> None:
    low = incident_risk(
        {
            "max_log_score": 0.1,
            "max_code_score": 0.0,
            "max_network_score": 0.0,
            "max_metrics_score": 0.0,
            "asset_criticality": 0.5,
            "model_count": 1,
            "deployment_age_minutes": 9999,
            "new_external_peer": False,
            "known_maintenance": False,
        }
    )
    high = incident_risk(
        {
            "max_log_score": 0.95,
            "max_code_score": 0.0,
            "max_network_score": 0.0,
            "max_metrics_score": 0.0,
            "asset_criticality": 0.5,
            "model_count": 1,
            "deployment_age_minutes": 9999,
            "new_external_peer": False,
            "known_maintenance": False,
        }
    )
    assert high > low


def test_a6_privilege_peer_rule() -> None:
    sev, cats = apply_deterministic_rules(
        {
            "max_network_score": 0.9,
            "new_external_peer": True,
            "auth_related_log": True,
            "log_category": "privilege_change",
            "max_metrics_score": 0.0,
            "max_code_score": 0.0,
            "deployment_age_minutes": 9999,
            "error_rate_anomaly": False,
            "known_maintenance": False,
            "deterministic_security_indicator": False,
            "network_new_external_peer": True,
            "code_category": None,
            "deployment_commit_matches": False,
        },
        "medium",
    )
    assert sev == "high"
    assert "suspicious_egress" in cats


def test_multi_model_high_risk():
    findings = [
        FindingView(
            finding_id="f1",
            finding_type="log_anomaly",
            tenant_id="t1",
            asset_id="host-1",
            service_id="payments-api",
            calibrated_score=0.94,
            model_name="log-transformer",
            contributors=[{"type": "unexpected_template", "template_id": "tpl-privilege-change"}],
            context={"deployment_age_minutes": 12},
        ),
        FindingView(
            finding_id="f2",
            finding_type="network_anomaly",
            tenant_id="t1",
            asset_id="host-1",
            service_id="payments-api",
            calibrated_score=0.91,
            model_name="flow-transformer",
            contributors=[{"type": "new_external_peer"}],
            context={"deployment_age_minutes": 12},
        ),
        FindingView(
            finding_id="f3",
            finding_type="metrics_anomaly",
            tenant_id="t1",
            asset_id="host-1",
            service_id="payments-api",
            calibrated_score=0.87,
            model_name="metrics-transformer",
            contributors=[{"metric": "http.error_rate", "observed": 0.08, "expected": 0.01}],
            context={"deployment_age_minutes": 12},
        ),
        FindingView(
            finding_id="f4",
            finding_type="code_risk",
            tenant_id="t1",
            asset_id="host-1",
            service_id="payments-api",
            calibrated_score=0.88,
            model_name="code-transformer",
            contributors=[{"file": "src/auth/session.py", "start_line": 104}],
            context={"deployment_age_minutes": 12},
        ),
    ]
    features = feature_vector(findings, asset_criticality=0.9)
    assert features["model_count"] == 4
    risk = incident_risk(features)
    assert risk > 0.8
    incident = build_incident_payload(findings, medium=0.6, high=0.8, critical=0.93)
    assert incident["severity"] in {"high", "critical"}
    assert len(incident["finding_ids"]) == 4
