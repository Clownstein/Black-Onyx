#!/usr/bin/env python3
"""Create the platform Postgres databases when an existing cluster predates init SQL."""

from __future__ import annotations

import argparse
import os
import time
from urllib.parse import urlsplit, urlunsplit

import psycopg
from psycopg import sql

DEFAULT_DATABASES = ("black_onyx", "security_gateway")


def admin_database_url(database_url: str) -> str:
    parsed = urlsplit(database_url.replace("postgresql+psycopg://", "postgresql://", 1))
    return urlunsplit(parsed._replace(path="/postgres"))


def _connect_when_ready(url: str, wait_seconds: float) -> psycopg.Connection:
    """Retry until Postgres accepts connections (fresh containers take a while)."""
    deadline = time.monotonic() + wait_seconds
    while True:
        try:
            return psycopg.connect(url, autocommit=True, connect_timeout=5)
        except psycopg.OperationalError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(2)


def ensure_databases(
    database_url: str,
    databases: tuple[str, ...] = DEFAULT_DATABASES,
    *,
    wait_seconds: float = 0,
) -> list[str]:
    created: list[str] = []
    with _connect_when_ready(admin_database_url(database_url), wait_seconds) as connection:
        for database in databases:
            exists = connection.execute(
                "SELECT 1 FROM pg_database WHERE datname = %s",
                (database,),
            ).fetchone()
            if exists is not None:
                continue
            connection.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(database)))
            created.append(database)
    return created


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--database-url",
        default=os.environ.get("ENSURE_DATABASE_URL", ""),
        help="Admin-capable Postgres URL (defaults to $ENSURE_DATABASE_URL to keep it off argv)",
    )
    parser.add_argument("--wait-seconds", type=float, default=120)
    args = parser.parse_args()
    if not args.database_url:
        parser.error("--database-url or ENSURE_DATABASE_URL is required")
    created = ensure_databases(args.database_url, wait_seconds=args.wait_seconds)
    if created:
        print("Created Postgres databases: " + ", ".join(created))
    else:
        print("Postgres databases already exist")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
