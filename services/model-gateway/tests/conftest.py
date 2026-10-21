import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
for mod in list(sys.modules):
    if mod == "app" or mod.startswith("app."):
        del sys.modules[mod]


@pytest.fixture(autouse=True)
def configured_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    from typing import Any

    from model_gateway import main as main_mod
    from model_gateway.config import settings

    monkeypatch.setattr(settings, "api_key", "test-model-key")
    async def confirmed_aliases(_model: str, _tenant: str) -> dict[str, Any]:
        return {
            alias: {
                "version": "test-version", "signature": "test-signature",
                "generation": 1, "confirmed": True,
            }
            for alias in ("champion", "canary", "shadow")
        }

    monkeypatch.setattr(main_mod, "serving_aliases", confirmed_aliases)
