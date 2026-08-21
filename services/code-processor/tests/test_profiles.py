from __future__ import annotations

import pytest
from code_processor.pipeline import compliance_from_env, process_code_change
from code_processor.scanners import _profile_config_dirs, _semgrep_configs

_PROFILE_ENV = (
    "PROFILE_PACK_IDS",
    "COMPLIANCE_CHECK_IDS",
    "PROFILE_SURFACES",
    "PROFILE_AUTOMATION",
    "SEMGREP_PROFILE_CONFIGS",
    "SEMGREP_CONFIG",
)


@pytest.fixture(autouse=True)
def _clear_profile_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in _PROFILE_ENV:
        monkeypatch.delenv(name, raising=False)


def test_semgrep_profile_configs_resolves_existing_dirs(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(
        "SEMGREP_PROFILE_CONFIGS",
        "profiles/owasp-asvs, profiles/secrets-scan , profiles/does-not-exist",
    )
    dirs = [d.replace("\\", "/") for d in _profile_config_dirs()]
    assert len(dirs) == 2
    assert any(d.endswith("scanners/semgrep/rules/profiles/owasp-asvs") for d in dirs)
    assert any(d.endswith("scanners/semgrep/rules/profiles/secrets-scan") for d in dirs)
    # _semgrep_configs honors the profile dirs when set.
    assert [c.replace("\\", "/") for c in _semgrep_configs()] == dirs


def test_semgrep_configs_fallback_when_profiles_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SEMGREP_CONFIG", "auto")
    assert _profile_config_dirs() == []
    assert _semgrep_configs() == ["auto"]


def test_compliance_from_env_disabled_by_default() -> None:
    assert compliance_from_env() is None


def test_compliance_from_env_shape(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PROFILE_PACK_IDS", "owasp-asvs,pci-dss-4")
    monkeypatch.setenv("COMPLIANCE_CHECK_IDS", "iso.27001.app.injection")
    monkeypatch.setenv("PROFILE_SURFACES", "webapp,bogus,code")
    monkeypatch.setenv("PROFILE_AUTOMATION", "hybrid")
    compliance = compliance_from_env()
    assert compliance == {
        "profile_pack_ids": ["owasp-asvs", "pci-dss-4"],
        "check_ids": ["iso.27001.app.injection"],
        "surfaces": ["webapp", "code"],
        "automation": "hybrid",
    }


def test_compliance_defaults_surface_and_automation(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("COMPLIANCE_CHECK_IDS", "cis.v8.16.appsec")
    monkeypatch.setenv("PROFILE_AUTOMATION", "not-valid")
    compliance = compliance_from_env()
    assert compliance is not None
    assert compliance["profile_pack_ids"] == []
    assert compliance["surfaces"] == ["code"]
    assert compliance["automation"] == "auto"


def test_pipeline_attaches_compliance(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PROFILE_PACK_IDS", "owasp-asvs")
    result = process_code_change({"files": {"a.py": "def add(a, b):\n    return a + b\n"}})
    assert result["finding"]["compliance"]["profile_pack_ids"] == ["owasp-asvs"]
    assert result["finding"]["compliance"]["surfaces"] == ["code"]
    assert result["feature"]["compliance"]["automation"] == "auto"


def test_pipeline_omits_compliance_when_unset() -> None:
    result = process_code_change({"files": {"a.py": "def add(a, b):\n    return a + b\n"}})
    assert "compliance" not in result["finding"]
    assert "compliance" not in result["feature"]


def test_compliance_from_scanner_findings_via_map() -> None:
    from code_processor.bindings import compliance_from_scanner_findings

    block = compliance_from_scanner_findings(
        [{"rule_id": "owasp-asvs-eval-use", "metadata": {"profile": "owasp-asvs"}}]
    )
    assert block is not None
    assert "iso.27001.app.injection" in block["check_ids"]
    assert "owasp-asvs" in block["profile_pack_ids"]
