"""Run security-gateway schema migrations before starting the HTTP server."""

from __future__ import annotations

import os
from pathlib import Path

import uvicorn
from alembic import command
from alembic.config import Config

from security_gateway.db import ensure_gateway_schema


def require_database_url() -> None:
    """Postgres is the only system of record for the running gateway."""
    if (os.environ.get("SECURITY_GATEWAY_DATABASE_URL") or "").strip():
        return
    raise SystemExit("SECURITY_GATEWAY_DATABASE_URL is required (Postgres is the system of record).")


def migrate_if_configured() -> None:
    if not (os.environ.get("SECURITY_GATEWAY_DATABASE_URL") or "").strip():
        return
    ini_path = Path(os.environ.get("SECURITY_GATEWAY_ALEMBIC_INI", "/app/alembic.ini"))
    if not ini_path.is_file():
        raise RuntimeError(f"Security gateway Alembic config is missing: {ini_path}")
    command.upgrade(Config(str(ini_path)), "head")


def main() -> None:
    require_database_url()
    migrate_if_configured()
    if (os.environ.get("SECURITY_GATEWAY_DATABASE_URL") or "").strip():
        ensure_gateway_schema()
    uvicorn.run(
        "security_gateway.app:app",
        host="0.0.0.0",
        port=8000,
    )


if __name__ == "__main__":
    main()
