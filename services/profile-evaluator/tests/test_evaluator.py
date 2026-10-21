from __future__ import annotations

import httpx
import respx
from profile_evaluator.client import IncidentApiClient
from profile_evaluator.config import Settings
from profile_evaluator.evaluator import ProfileEvaluator

BASE = "http://incident-api.test"


def _settings() -> Settings:
    return Settings(
        _env_file=None,
        INCIDENT_API_URL=BASE,
        PROFILE_EVALUATOR_TENANT_ID="tenant-acme",
    )


def _evaluator(settings: Settings) -> ProfileEvaluator:
    return ProfileEvaluator(settings, IncidentApiClient(settings))


def _profiles_payload() -> dict:
    return {
        "items": [
            {"profile_id": "spf-1", "active": True, "name": "prod"},
            {"profile_id": "spf-2", "active": False, "name": "disabled"},
        ]
    }


def _coverage(status: str) -> dict:
    return {
        "profile_id": "spf-1",
        "coverage": [
            {
                "check_id": "cis.v8.16.appsec",
                "title": "AppSec",
                "status": status,
                "reason": None if status == "pass" else "open_finding",
                "automation": "auto",
                "surfaces": ["webapp"],
                "pack_ids": ["cis-appsec"],
                "severity_default": "high",
            }
        ],
        "summary": {},
    }


@respx.mock
def test_pass_to_fail_emits_finding() -> None:
    settings = _settings()
    evaluator = _evaluator(settings)

    respx.get(f"{BASE}/api/v1/security-profiles").mock(
        return_value=httpx.Response(200, json=_profiles_payload())
    )
    eval_route = respx.post(f"{BASE}/api/v1/security-profiles/spf-1/evaluate")
    finding_route = respx.post(f"{BASE}/api/v1/findings").mock(
        return_value=httpx.Response(201, json={"finding_id": "x"})
    )

    # First cycle: check passes → no finding emitted.
    eval_route.mock(return_value=httpx.Response(200, json=_coverage("pass")))
    first = evaluator.evaluate_once()
    assert first["active_count"] == 1
    assert first["evaluated_profiles"] == ["spf-1"]
    assert first["emitted_findings"] == []
    assert finding_route.call_count == 0

    # Second cycle: same check now fails → synthetic finding emitted.
    eval_route.mock(return_value=httpx.Response(200, json=_coverage("fail")))
    second = evaluator.evaluate_once()
    assert second["emitted_findings"] == ["profile-eval-spf-1-cis.v8.16.appsec"]
    assert finding_route.call_count == 1

    sent = finding_route.calls.last.request
    body = sent.content.decode()
    assert "compliance_regression" in body
    assert "cis-appsec" in body
    # Tenant + role headers forwarded to incident-api.
    assert sent.headers["X-Tenant-Id"] == "tenant-acme"


@respx.mock
def test_no_finding_when_stays_failing() -> None:
    settings = _settings()
    evaluator = _evaluator(settings)

    respx.get(f"{BASE}/api/v1/security-profiles").mock(
        return_value=httpx.Response(200, json=_profiles_payload())
    )
    respx.post(f"{BASE}/api/v1/security-profiles/spf-1/evaluate").mock(
        return_value=httpx.Response(200, json=_coverage("fail"))
    )
    finding_route = respx.post(f"{BASE}/api/v1/findings").mock(
        return_value=httpx.Response(201, json={"finding_id": "x"})
    )

    # fail on first observation is not a pass→fail transition.
    evaluator.evaluate_once()
    # still failing on the second cycle → no new finding.
    evaluator.evaluate_once()
    assert finding_route.call_count == 0


@respx.mock
def test_synthetic_finding_is_schema_shaped() -> None:
    settings = _settings()
    evaluator = _evaluator(settings)
    check = {
        "check_id": "iso.27001.app.secrets",
        "title": "Secrets",
        "status": "fail",
        "automation": "hybrid",
        "surfaces": ["webapp", "code"],
        "pack_ids": ["secrets-scan"],
        "severity_default": "critical",
    }
    finding = evaluator._build_finding("spf-9", check)
    for key in (
        "finding_id",
        "finding_type",
        "asset_id",
        "model_name",
        "model_version",
        "raw_score",
        "calibrated_score",
        "window",
        "compliance",
    ):
        assert key in finding
    assert finding["calibrated_score"] == 0.9
    assert finding["severity_hint"] == "critical"
    assert finding["compliance"]["check_ids"] == ["iso.27001.app.secrets"]
    assert finding["compliance"]["automation"] == "hybrid"
    names = {c["name"] for c in finding["contributors"]}
    assert "vector_novelty" in names
