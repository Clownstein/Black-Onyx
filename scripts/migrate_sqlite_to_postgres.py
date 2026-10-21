#!/usr/bin/env python3
"""One-way ETL: legacy SQLite state → Postgres auth/tip/security_gateway schemas."""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import create_engine, text
from sqlalchemy.exc import SQLAlchemyError

TIP_SQLITE_FILES = (
    "feeds.sqlite",
    "connectors.sqlite",
    "watchlists.sqlite",
    "webhooks.sqlite",
    "annotations.sqlite",
    "ioc_decay.sqlite",
    "cases.sqlite",
    "assets.sqlite",
    "detection_rules.sqlite",
    "taxii_publish.sqlite",
    "ingestion_checkpoint.sqlite",
    "chat_sessions.sqlite",
    "misp.sqlite",
    "enrichment_cache.sqlite",
    "playbooks.sqlite",
)

AUTH_SQLITE = "black_onyx.sqlite"


def _table_names(sqlite_path: Path) -> list[str]:
    conn = sqlite3.connect(f"file:{sqlite_path}?mode=ro", uri=True)
    try:
        rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        ).fetchall()
        return [str(row[0]) for row in rows]
    finally:
        conn.close()


def _row_count(sqlite_path: Path, table: str) -> int:
    conn = sqlite3.connect(f"file:{sqlite_path}?mode=ro", uri=True)
    try:
        return int(conn.execute(f"SELECT COUNT(*) FROM [{table}]").fetchone()[0])
    finally:
        conn.close()


def _copy_sqlite_table(
    *,
    source: Path,
    table: str,
    engine_url: str,
    target_schema: str,
    target_table: str | None = None,
) -> int:
    target_table = target_table or table
    source_conn = sqlite3.connect(f"file:{source}?mode=ro", uri=True)
    source_conn.row_factory = sqlite3.Row
    try:
        rows = source_conn.execute(f"SELECT * FROM [{table}]").fetchall()
    finally:
        source_conn.close()
    if not rows:
        return 0
    columns = rows[0].keys()
    col_list = ", ".join(f'"{c}"' for c in columns)
    placeholders = ", ".join(f":{c}" for c in columns)
    insert_sql = (
        f'INSERT INTO "{target_schema}"."{target_table}" ({col_list}) '
        f"VALUES ({placeholders}) ON CONFLICT DO NOTHING"
    )
    engine = create_engine(engine_url)
    inserted = 0
    with engine.begin() as conn:
        conn.execute(text(f'SET search_path TO "{target_schema}"'))
        for row in rows:
            result = conn.execute(text(insert_sql), dict(row))
            inserted += result.rowcount or 0
    engine.dispose()
    return inserted


def _postgres_count(engine_url: str, schema: str, table: str) -> int:
    engine = create_engine(engine_url)
    with engine.connect() as conn:
        value = conn.execute(
            text(f'SELECT COUNT(*) FROM "{schema}"."{table}"')
        ).scalar()
    engine.dispose()
    return int(value or 0)


def _cutover_completed(engine_url: str, domain: str) -> bool:
    engine = create_engine(engine_url)
    try:
        with engine.connect() as conn:
            table = conn.execute(
                text("SELECT to_regclass('public.platform_cutover')")
            ).scalar()
            if table is None:
                return False
            return bool(
                conn.execute(
                    text(
                        "SELECT 1 FROM public.platform_cutover "
                        "WHERE domain = :domain"
                    ),
                    {"domain": domain},
                ).scalar()
            )
    except SQLAlchemyError:
        return False
    finally:
        engine.dispose()


def _write_cutover(
    engine_url: str,
    domain: str,
    sqlite_counts: dict[str, int],
    pg_counts: dict[str, int],
    marker_dir: Path | None = None,
) -> None:
    engine = create_engine(engine_url)
    payload = {
        "domain": domain,
        "sqlite_counts": sqlite_counts,
        "postgres_counts": pg_counts,
        "migrated_at": datetime.now(timezone.utc).isoformat(),
    }
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO public.platform_cutover (domain, sqlite_counts, postgres_counts, migrated_at) "
                "VALUES (:domain, CAST(:sqlite AS jsonb), CAST(:postgres AS jsonb), now()) "
                "ON CONFLICT (domain) DO UPDATE SET "
                "sqlite_counts = EXCLUDED.sqlite_counts, "
                "postgres_counts = EXCLUDED.postgres_counts, "
                "migrated_at = EXCLUDED.migrated_at"
            ),
            {
                "domain": domain,
                "sqlite": json.dumps(sqlite_counts),
                "postgres": json.dumps(pg_counts),
            },
        )
    engine.dispose()
    marker_root = marker_dir or Path(os.environ.get("BLACK_ONYX_STATE_DIR", "."))
    marker = marker_root / ".postgres_cutover.json"
    marker_payload: dict[str, Any] = {"format_version": 1, "domains": {}}
    if marker.is_file():
        try:
            existing = json.loads(marker.read_text(encoding="utf-8"))
            if isinstance(existing, dict) and isinstance(existing.get("domains"), dict):
                marker_payload = existing
        except (OSError, ValueError):
            pass
    marker_payload["domains"][domain] = payload
    marker.write_text(json.dumps(marker_payload, indent=2), encoding="utf-8")


def verify_migrated_counts(
    domain: str,
    sqlite_counts: dict[str, int],
    postgres_counts: dict[str, int],
) -> None:
    failures: list[str] = []
    for source_table, source_count in sqlite_counts.items():
        target_table = source_table.rsplit(":", 1)[-1]
        target_count = postgres_counts.get(target_table, 0)
        if target_count < source_count:
            failures.append(
                f"{source_table}: source={source_count}, postgres={target_count}"
            )
    if failures:
        raise RuntimeError(
            f"{domain} row-count verification failed: " + "; ".join(failures)
        )


def migrate_auth(state_dir: Path, database_url: str) -> dict[str, Any]:
    if _cutover_completed(database_url, "auth"):
        return {"skipped": True, "reason": "auth cutover already completed"}
    source = state_dir / AUTH_SQLITE
    if not source.is_file():
        return {"skipped": True, "reason": f"missing {AUTH_SQLITE}"}
    sqlite_counts: dict[str, int] = {}
    pg_counts: dict[str, int] = {}
    copied = 0
    for table in _table_names(source):
        sqlite_counts[table] = _row_count(source, table)
        copied += _copy_sqlite_table(
            source=source, table=table, engine_url=database_url, target_schema="auth"
        )
        pg_counts[table] = _postgres_count(database_url, "auth", table)
    verify_migrated_counts("auth", sqlite_counts, pg_counts)
    _write_cutover(database_url, "auth", sqlite_counts, pg_counts, state_dir)
    return {"tables": len(sqlite_counts), "rows_attempted": copied, "sqlite_counts": sqlite_counts, "postgres_counts": pg_counts}


def migrate_tip(state_dir: Path, database_url: str) -> dict[str, Any]:
    if _cutover_completed(database_url, "tip"):
        return {"skipped": True, "reason": "tip cutover already completed"}
    sqlite_counts: dict[str, int] = {}
    pg_counts: dict[str, int] = {}
    copied = 0
    seen_tables: set[str] = set()
    for name in TIP_SQLITE_FILES:
        source = state_dir / name
        if not source.is_file():
            continue
        for table in _table_names(source):
            if table in seen_tables:
                # Never drop a second file's rows silently; resolve by hand.
                raise RuntimeError(
                    f"table {table!r} exists in more than one TIP SQLite file (latest: {name})"
                )
            seen_tables.add(table)
            sqlite_counts[f"{name}:{table}"] = _row_count(source, table)
            copied += _copy_sqlite_table(
                source=source, table=table, engine_url=database_url, target_schema="tip"
            )
            pg_counts[table] = _postgres_count(database_url, "tip", table)
    verify_migrated_counts("tip", sqlite_counts, pg_counts)
    _write_cutover(database_url, "tip", sqlite_counts, pg_counts, state_dir)
    return {"tables": len(seen_tables), "rows_attempted": copied, "sqlite_counts": sqlite_counts, "postgres_counts": pg_counts}


def migrate_security_gateway(
    approval_db: Path | None,
    challenge_db: Path | None,
    database_url: str,
) -> dict[str, Any]:
    if _cutover_completed(database_url, "security_gateway"):
        return {
            "skipped": True,
            "reason": "security_gateway cutover already completed",
        }
    sqlite_counts: dict[str, int] = {}
    pg_counts: dict[str, int] = {}
    copied = 0
    for label, path, tables in (
        ("approvals", approval_db, ("approvals", "agent_runs", "schema_migrations")),
        ("challenges", challenge_db, ("challenge_solves",)),
    ):
        if path is None or not path.is_file():
            continue
        for table in tables:
            if table not in _table_names(path):
                continue
            sqlite_counts[f"{label}:{table}"] = _row_count(path, table)
            copied += _copy_sqlite_table(
                source=path, table=table, engine_url=database_url, target_schema="public"
            )
            pg_counts[table] = _postgres_count(database_url, "public", table)
    verify_migrated_counts("security_gateway", sqlite_counts, pg_counts)
    _write_cutover(
        database_url,
        "security_gateway",
        sqlite_counts,
        pg_counts,
        approval_db.parent if approval_db is not None else None,
    )
    return {"rows_attempted": copied, "sqlite_counts": sqlite_counts, "postgres_counts": pg_counts}


def _run_alembic(repo_root: Path, ini_path: Path, env: dict[str, str]) -> None:
    subprocess.run(
        [sys.executable, "-m", "alembic", "-c", str(ini_path), "upgrade", "head"],
        cwd=repo_root,
        env=env,
        check=True,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", type=Path, required=True, help="Black Onyx storage.state_dir")
    parser.add_argument(
        "--black-onyx-database-url",
        default=os.environ.get("BLACK_ONYX_DATABASE_URL", ""),
        help="Postgres URL for black_onyx database (auth+tip schemas)",
    )
    parser.add_argument(
        "--security-gateway-database-url",
        default=os.environ.get("SECURITY_GATEWAY_DATABASE_URL", ""),
        help="Postgres URL for security_gateway database",
    )
    parser.add_argument(
        "--approval-db",
        type=Path,
        default=Path(os.environ.get("SECURITY_APPROVAL_DB", "/app/state/approvals.db")),
    )
    parser.add_argument(
        "--challenge-db",
        type=Path,
        default=Path(os.environ.get("SECURITY_CHALLENGE_DB", "/app/state/challenges.sqlite3")),
    )
    parser.add_argument("--skip-alembic", action="store_true", help="Assume schemas already migrated")
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()

    if not args.black_onyx_database_url:
        print("BLACK_ONYX_DATABASE_URL is required", file=sys.stderr)
        return 2

    env = os.environ.copy()
    env["BLACK_ONYX_DATABASE_URL"] = args.black_onyx_database_url
    if not args.skip_alembic:
        _run_alembic(args.repo_root, args.repo_root / "alembic.ini", env)

    summary: dict[str, Any] = {"auth": migrate_auth(args.state_dir, args.black_onyx_database_url)}
    summary["tip"] = migrate_tip(args.state_dir, args.black_onyx_database_url)

    if args.security_gateway_database_url:
        gw_env = env.copy()
        gw_env["SECURITY_GATEWAY_DATABASE_URL"] = args.security_gateway_database_url
        if not args.skip_alembic:
            _run_alembic(
                args.repo_root / "services" / "security-gateway",
                args.repo_root / "services" / "security-gateway" / "alembic.ini",
                gw_env,
            )
        summary["security_gateway"] = migrate_security_gateway(
            args.approval_db,
            args.challenge_db,
            args.security_gateway_database_url,
        )

    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
