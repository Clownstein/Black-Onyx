"""security-gateway refuses to start without its Postgres system of record."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

GATEWAY_ROOT = Path(__file__).resolve().parents[1] / "services" / "security-gateway"
if str(GATEWAY_ROOT) not in sys.path:
    sys.path.insert(0, str(GATEWAY_ROOT))


def test_startup_refuses_without_database_url(monkeypatch: pytest.MonkeyPatch) -> None:
    from security_gateway import startup

    monkeypatch.delenv("SECURITY_GATEWAY_DATABASE_URL", raising=False)
    with pytest.raises(SystemExit, match="SECURITY_GATEWAY_DATABASE_URL is required"):
        startup.require_database_url()
    monkeypatch.setenv("SECURITY_GATEWAY_DATABASE_URL", "postgresql+psycopg://u:p@db/gw")
    startup.require_database_url()
