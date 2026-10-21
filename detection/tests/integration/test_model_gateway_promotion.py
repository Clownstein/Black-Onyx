"""Canary/shadow alias promotion checks for model-gateway routing."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
GW = ROOT / "services" / "model-gateway"
if str(GW) not in sys.path:
    sys.path.insert(0, str(GW))

from model_gateway.routing import select_alias_for_request  # noqa: E402


def test_canary_promotion_rollout_percentages() -> None:
    tenants = [f"tenant-{index}" for index in range(200)]
    for percent in (0, 10, 50, 100):
        canary = sum(
            1 for tenant in tenants
            if select_alias_for_request(None, tenant, canary_percent=percent) == "canary"
        )
        if percent == 0:
            assert canary == 0
        elif percent == 100:
            assert canary == len(tenants)
        else:
            assert 0 < canary < len(tenants)


def test_explicit_champion_after_shadow_probe() -> None:
    assert select_alias_for_request("champion", "tenant-shadow", canary_percent=100) == "champion"
