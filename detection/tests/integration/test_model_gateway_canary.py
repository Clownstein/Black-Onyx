"""Integration checks for model-gateway canary/shadow alias routing."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
GW = ROOT / "services" / "model-gateway"
if str(GW) not in sys.path:
    sys.path.insert(0, str(GW))

from model_gateway.routing import select_alias_for_request, tenant_bucket  # noqa: E402


def test_canary_bucket_is_stable_for_tenant() -> None:
    tenant = "tenant-shadow-promote-01"
    assert tenant_bucket(tenant) == tenant_bucket(tenant)
    assert 0 <= tenant_bucket(tenant) < 100


def test_explicit_shadow_alias_wins_over_canary_percent() -> None:
    assert select_alias_for_request("shadow", "tenant-a", canary_percent=100) == "shadow"


def test_canary_percent_zero_always_champion() -> None:
    assert select_alias_for_request(None, "tenant-b", canary_percent=0) == "champion"


def test_canary_percent_hundred_always_canary() -> None:
    assert select_alias_for_request(None, "tenant-c", canary_percent=100) == "canary"
