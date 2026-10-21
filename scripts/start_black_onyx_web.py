#!/usr/bin/env python3
"""Run platform Alembic migrations before starting the web application."""

from __future__ import annotations

import os
from pathlib import Path

from alembic import command
from alembic.config import Config

from sqlalchemy import text

from black_onyx.db.config import black_onyx_database_url
from black_onyx.db.sql_compat import create_postgres_compat_engine
from black_onyx.db.tip_store import _ensure_tip_postgres_schema


def require_database_url() -> None:
    """Postgres is the only system of record for the running web service."""
    if black_onyx_database_url():
        return
    raise SystemExit(
        "BLACK_ONYX_DATABASE_URL is required (Postgres is the system of record). "
        "Run scripts/bootstrap_full_stack.sh to provision it."
    )


def migrate_if_configured() -> None:
    if not black_onyx_database_url():
        return
    ini_path = Path(os.environ.get("BLACK_ONYX_ALEMBIC_INI", "/app/alembic.ini"))
    if not ini_path.is_file():
        raise RuntimeError(f"Black Onyx Alembic config is missing: {ini_path}")
    command.upgrade(Config(str(ini_path)), "head")


def ensure_auth_schema_after_migrate() -> None:
    """Fail closed if auth.users is missing after Alembic upgrade."""
    url = black_onyx_database_url()
    if not url:
        return
    engine = create_postgres_compat_engine(url, "auth")
    try:
        with engine.connect() as conn:
            conn.execute(text('SET search_path TO "auth"'))
            conn.execute(text("SELECT 1 FROM users LIMIT 1"))
            conn.execute(
                text(
                    "SELECT 1 FROM pg_indexes "
                    "WHERE schemaname = 'auth' AND indexname = 'ux_users_email_lower'"
                )
            ).one()
    except Exception as exc:
        raise RuntimeError(
            "auth schema is not migrated (users / ux_users_email_lower missing). "
            "Run `alembic upgrade head` before startup."
        ) from exc
    finally:
        engine.dispose()


def ensure_tip_schema_after_migrate() -> None:
    """Fail closed if tip schema is missing after Alembic upgrade."""
    url = black_onyx_database_url()
    if not url:
        return
    engine = create_postgres_compat_engine(url, "tip")
    try:
        _ensure_tip_postgres_schema(engine)
    finally:
        engine.dispose()


def main() -> None:
    require_database_url()
    migrate_if_configured()
    ensure_auth_schema_after_migrate()
    ensure_tip_schema_after_migrate()
    os.execvp(
        "black-onyx-web",
        ["black-onyx-web", "--host", "0.0.0.0", "--port", "8000"],
    )


if __name__ == "__main__":
    main()
