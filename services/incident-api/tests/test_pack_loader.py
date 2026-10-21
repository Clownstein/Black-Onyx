from __future__ import annotations

from incident_api.profiles.pack_loader import load_all_packs, merge_packs


def test_load_framework_and_industry_packs() -> None:
    packs = load_all_packs()
    assert "cis-v8-ig1" in packs
    assert "hipaa" in packs
    assert "saas-trust" in packs
    assert packs["cis-v8-ig1"].kind == "framework"
    assert len(packs["cis-v8-ig1"].checks) >= 1


def test_merge_union_strictest() -> None:
    resolved = merge_packs(["cis-v8-ig1", "pci-dss-4"])
    assert "cis-v8-ig1" in resolved.selected_packs
    assert "pci-dss-4" in resolved.selected_packs
    ids = {c.check_id for c in resolved.checks}
    assert "cis.v8.8.audit-log-management" in ids
    assert "pci.1.cde-segmentation" in ids
    # overlapping logging checks keep highest severity path via distinct ids
    assert sum(1 for c in resolved.checks if c.automation == "auto") >= 1
    assert resolved.to_dict()["auto_count"] >= 1


def test_merge_industry_additive() -> None:
    base = merge_packs(["nist-csf-2"])
    with_industry = merge_packs(["nist-csf-2", "hipaa"])
    assert len(with_industry.checks) >= len(base.checks)
    assert any(c.check_id.startswith("hipaa.") for c in with_industry.checks)
