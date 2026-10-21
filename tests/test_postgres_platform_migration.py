"""Postgres platform migration helpers and TipStore wiring."""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path

import pytest

from black_onyx.auth.database import StateDatabase, reset_auth_store_cache_for_tests
from black_onyx.db.sql_compat import postgres_compat_connection
from black_onyx.db.tip_store import connect_tip_store, reset_tip_store_cache_for_tests
from black_onyx.feeds.feed_manager import FeedManager

_TEST_DB_URL = os.environ.get("BLACK_ONYX_TEST_DATABASE_URL", "")


@pytest.fixture(scope="module", autouse=True)
def _migrated_test_database():
    """Run the real platform Alembic migrations once against the test database."""
    if not _TEST_DB_URL:
        yield
        return
    from alembic import command
    from alembic.config import Config

    previous = os.environ.get("BLACK_ONYX_DATABASE_URL")
    os.environ["BLACK_ONYX_DATABASE_URL"] = _TEST_DB_URL
    try:
        command.upgrade(Config(str(Path(__file__).resolve().parents[1] / "alembic.ini")), "head")
    finally:
        if previous is None:
            os.environ.pop("BLACK_ONYX_DATABASE_URL", None)
        else:
            os.environ["BLACK_ONYX_DATABASE_URL"] = previous
    yield


def test_production_requires_black_onyx_database_url(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv("BLACK_ONYX_DATABASE_URL", raising=False)
    with pytest.raises(RuntimeError, match="BLACK_ONYX_DATABASE_URL"):
        StateDatabase(str(tmp_path), production=True)


def test_sqlite_state_database_still_bootstraps(tmp_path: Path) -> None:
    db = StateDatabase(str(tmp_path), production=False)
    with db.transaction() as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)")
    db.close()


def test_tip_store_sqlite_per_file_isolation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.delenv("BLACK_ONYX_DATABASE_URL", raising=False)
    reset_tip_store_cache_for_tests()
    feeds = FeedManager(persist_dir=str(tmp_path))
    feeds.add_feed("demo", "https://example.com/feed.xml", feed_type="rss")
    conn = connect_tip_store(tmp_path, "feeds.sqlite")
    assert isinstance(conn, sqlite3.Connection)
    row = conn.execute("SELECT COUNT(*) AS n FROM feeds").fetchone()
    assert int(row["n"]) == 1


@pytest.mark.skipif(not os.environ.get("BLACK_ONYX_TEST_DATABASE_URL"), reason="Set BLACK_ONYX_TEST_DATABASE_URL for integration test")
def test_postgres_auth_schema_after_alembic(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    url = os.environ["BLACK_ONYX_TEST_DATABASE_URL"]
    monkeypatch.setenv("BLACK_ONYX_DATABASE_URL", url)
    reset_auth_store_cache_for_tests()
    reset_tip_store_cache_for_tests()
    db = StateDatabase(str(tmp_path), production=True)
    db._conn.execute("SELECT 1 FROM users LIMIT 1")
    db.close()


@pytest.mark.skipif(not os.environ.get("BLACK_ONYX_TEST_DATABASE_URL"), reason="Set BLACK_ONYX_TEST_DATABASE_URL for integration test")
def test_postgres_compat_rollback_is_atomic() -> None:
    url = os.environ["BLACK_ONYX_TEST_DATABASE_URL"]
    with postgres_compat_connection(url, "public") as connection:
        connection.execute(
            "CREATE TEMPORARY TABLE compat_rollback_test "
            "(value TEXT NOT NULL) ON COMMIT PRESERVE ROWS"
        )
        connection.commit()
        connection.execute(
            "INSERT INTO compat_rollback_test (value) VALUES (?)",
            ("must-rollback",),
        )
        connection.rollback()
        row = connection.execute(
            "SELECT COUNT(*) AS count FROM compat_rollback_test"
        ).fetchone()
        assert row is not None
        assert row["count"] == 0


def test_compat_cursor_is_iterable() -> None:
    from black_onyx.db.sql_compat import CompatCursor

    cursor = CompatCursor(2, ["name"], [("alpha",), ("beta",)])
    assert [row["name"] for row in cursor] == ["alpha", "beta"]


def test_tip_schema_gate_fails_closed_when_feeds_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    from black_onyx.db import tip_store

    class _FakeConn:
        def __enter__(self):
            return self

        def __exit__(self, *_exc: object) -> None:
            return None

        def execute(self, statement):  # noqa: ANN001
            sql = str(statement)
            if "FROM \"feeds\"" in sql or "FROM feeds" in sql:
                raise RuntimeError('relation "feeds" does not exist')
            return None

    class _FakeEngine:
        def connect(self):
            return _FakeConn()

        def dispose(self) -> None:
            return None

    monkeypatch.setattr(
        tip_store, "create_postgres_compat_engine", lambda _url, _schema: _FakeEngine()
    )
    monkeypatch.setattr(tip_store, "black_onyx_database_url", lambda: "postgresql://unused")
    tip_store.reset_tip_store_cache_for_tests()
    with pytest.raises(RuntimeError, match="Missing tables:.*feeds"):
        tip_store.connect_tip_store(None, "feeds.sqlite")
    tip_store.reset_tip_store_cache_for_tests()


def test_compat_row_stringifies_datetimes() -> None:
    from datetime import datetime

    from black_onyx.db.sql_compat import CompatRow

    row = CompatRow(["last_poll"], [datetime(2026, 10, 3, 12, 30, 0)])
    assert row["last_poll"] == "2026-10-03 12:30:00"
    assert datetime.fromisoformat(row["last_poll"]).year == 2026


def test_compat_row_unpacks_values_like_sqlite() -> None:
    from black_onyx.db.sql_compat import CompatRow

    row = CompatRow(["role", "content", "images"], ["user", "hi", None])
    role, content, images = row
    assert (role, content, images) == ("user", "hi", None)
    assert dict(row) == {"role": "user", "content": "hi", "images": None}


def test_translate_sql_rewrites_collate_nocase() -> None:
    from black_onyx.db.sql_compat import _translate_sql

    assert (
        _translate_sql("SELECT * FROM users WHERE email=? COLLATE NOCASE")
        == "SELECT * FROM users WHERE LOWER(email) = LOWER(?)"
    )
    assert "COLLATE" not in _translate_sql(
        "CREATE TABLE users (email TEXT NOT NULL UNIQUE COLLATE NOCASE)"
    )


def test_build_insert_or_replace_targets_conflict_columns() -> None:
    from black_onyx.db.sql_compat import _build_insert_or_replace

    sql = _build_insert_or_replace(
        "INSERT OR REPLACE INTO feeds (name, url, feed_type, collection, enabled, "
        "poll_interval_minutes, config) VALUES (?, ?, ?, ?, ?, ?, ?)",
        ["name"],
    )
    assert "ON CONFLICT (name) DO UPDATE SET" in sql
    assert "name=EXCLUDED.name" in sql
    assert "url=EXCLUDED.url" in sql
    assert "INSERT OR REPLACE" not in sql.upper()


def test_build_insert_or_replace_composite_primary_key() -> None:
    from black_onyx.db.sql_compat import _build_insert_or_replace

    sql = _build_insert_or_replace(
        "INSERT OR REPLACE INTO confidence (collection, point_id, confidence_score, "
        "author, created_at) VALUES (?, ?, ?, ?, ?)",
        ["collection", "point_id"],
    )
    assert "ON CONFLICT (collection, point_id) DO UPDATE SET" in sql


def test_replace_conflict_allowlist_covers_production_call_sites() -> None:
    from black_onyx.db.sql_compat import REPLACE_CONFLICT_TARGETS

    expected = {
        "feeds": ("name",),
        "confidence": ("collection", "point_id"),
        "status": ("collection", "point_id"),
        "objects": ("collection_id", "object_id"),
        "enrichment_cache": ("cache_key",),
        "synced_events": ("event_id",),
        "synced_iocs": ("event_id", "ioc_type", "ioc_value"),
        "published": ("case_id", "misp_event_id"),
        "processed_items": ("file_hash", "chunk_index", "collection"),
        "ingestion_runs": ("run_id",),
    }
    assert REPLACE_CONFLICT_TARGETS == expected


def test_replace_conflict_targets_match_alembic_primary_keys() -> None:
    import re

    from black_onyx.db.sql_compat import REPLACE_CONFLICT_TARGETS

    root = Path(__file__).resolve().parents[1]
    alembic = (root / "alembic" / "versions" / "0003_tip_state.py").read_text(
        encoding="utf-8"
    )
    for table, cols in REPLACE_CONFLICT_TARGETS.items():
        table_match = re.search(
            rf"CREATE TABLE IF NOT EXISTS {table} \((.*?)\)\s*;",
            alembic,
            re.DOTALL,
        )
        assert table_match is not None, f"missing alembic table {table}"
        body = table_match.group(1)
        if len(cols) == 1:
            assert (
                re.search(rf"\b{cols[0]}\b[^,\n]*PRIMARY KEY", body, re.IGNORECASE)
                or f"PRIMARY KEY ({cols[0]})" in body.replace(" ", "")
                or f"PRIMARY KEY({cols[0]})" in body.replace(" ", "")
            ), f"{table}.{cols[0]} not primary key"
        else:
            joined = ", ".join(cols)
            assert f"PRIMARY KEY ({joined})" in body or f"PRIMARY KEY({joined})" in body.replace(
                " ", ""
            ), f"{table} PK {joined} missing in alembic"


@pytest.mark.skipif(
    not os.environ.get("BLACK_ONYX_TEST_DATABASE_URL"),
    reason="Set BLACK_ONYX_TEST_DATABASE_URL for integration test",
)
def test_postgres_insert_or_replace_upserts_by_primary_key() -> None:
    url = os.environ["BLACK_ONYX_TEST_DATABASE_URL"]
    with postgres_compat_connection(url, "public") as connection:
        connection.execute(
            "CREATE TEMPORARY TABLE compat_replace_test ("
            "name TEXT PRIMARY KEY, value TEXT NOT NULL"
            ") ON COMMIT PRESERVE ROWS"
        )
        connection.commit()
        connection.execute(
            "INSERT OR REPLACE INTO compat_replace_test (name, value) VALUES (?, ?)",
            ("alpha", "one"),
        )
        connection.commit()
        connection.execute(
            "INSERT OR REPLACE INTO compat_replace_test (name, value) VALUES (?, ?)",
            ("alpha", "two"),
        )
        connection.commit()
        row = connection.execute(
            "SELECT value FROM compat_replace_test WHERE name = ?",
            ("alpha",),
        ).fetchone()
        assert row is not None
        assert row["value"] == "two"
        count = connection.execute(
            "SELECT COUNT(*) AS n FROM compat_replace_test"
        ).fetchone()
        assert count is not None
        assert int(count["n"]) == 1


def test_web_dockerfile_ships_pg_dump_tools() -> None:
    root = Path(__file__).resolve().parents[1]
    dockerfile = (root / "Dockerfile").read_text(encoding="utf-8")
    assert "AS pg-tools" in dockerfile
    assert "postgresql-client" in dockerfile
    assert "pg_dump" in dockerfile
    assert "pg_restore" in dockerfile
    assert "/usr/lib/postgresql/*/bin" in dockerfile
    assert "COPY --from=pg-tools /pg-tools/bin/" in dockerfile
    assert "7f 45 4c 46" in dockerfile
    assert "LD_LIBRARY_PATH=/pg-tools/lib" in dockerfile


def test_bootstrap_generates_misp_tls_material() -> None:
    root = Path(__file__).resolve().parents[1]
    sh = (root / "scripts" / "bootstrap_full_stack.sh").read_text(encoding="utf-8")
    ps1 = (root / "scripts" / "bootstrap_full_stack.ps1").read_text(encoding="utf-8")
    assert "data/misp-ssl" in sh
    assert "openssl req -x509" in sh
    assert "dhparams.pem" in sh
    assert "exit 2" in sh
    assert "ERROR: failed to generate data/misp-ssl" in sh
    assert "misp-ssl" in ps1
    assert "openssl req -x509" in ps1
    assert "throw" in ps1 and "misp-ssl" in ps1
    assert "--build-arg" in ps1
    assert "TOOLBOX_BASE_IMAGE" in ps1


def test_auth_email_ci_unique_migration_exists() -> None:
    root = Path(__file__).resolve().parents[1]
    migration = (
        root / "alembic" / "versions" / "0004_auth_email_ci_unique.py"
    ).read_text(encoding="utf-8")
    assert "ux_users_email_lower" in migration
    assert "LOWER(email)" in migration
    assert "DELETE FROM users WHERE LOWER(email)" in migration


@pytest.mark.skipif(
    not os.environ.get("BLACK_ONYX_TEST_DATABASE_URL"),
    reason="Set BLACK_ONYX_TEST_DATABASE_URL for integration test",
)
def test_postgres_auth_email_unique_is_case_insensitive(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    url = os.environ["BLACK_ONYX_TEST_DATABASE_URL"]
    monkeypatch.setenv("BLACK_ONYX_DATABASE_URL", url)
    reset_auth_store_cache_for_tests()
    db = StateDatabase(str(tmp_path), production=True)
    try:
        db._conn.execute(
            "INSERT INTO users(user_id,email,display_name,password_hash,role,created_at,updated_at) "
            "VALUES(?,?,?,?,?,?,?)",
            (
                "user-ci-1",
                "analyst@example.com",
                "Analyst",
                "hash",
                "analyst",
                "2026-01-01T00:00:00",
                "2026-01-01T00:00:00",
            ),
        )
        db._conn.commit()
        with pytest.raises(Exception):
            db._conn.execute(
                "INSERT INTO users(user_id,email,display_name,password_hash,role,created_at,updated_at) "
                "VALUES(?,?,?,?,?,?,?)",
                (
                    "user-ci-2",
                    "Analyst@Example.com",
                    "Analyst Two",
                    "hash",
                    "analyst",
                    "2026-01-01T00:00:00",
                    "2026-01-01T00:00:00",
                ),
            )
            db._conn.commit()
        db._conn.rollback()
        row = db._conn.execute(
            "SELECT email FROM users WHERE email=? COLLATE NOCASE",
            ("ANALYST@EXAMPLE.COM",),
        ).fetchone()
        assert row is not None
        assert row["email"] == "analyst@example.com"
    finally:
        try:
            db._conn.execute("DELETE FROM users WHERE user_id LIKE 'user-ci-%'")
            db._conn.commit()
        except Exception:
            db._conn.rollback()
        db.close()
        reset_auth_store_cache_for_tests()


def test_windows_bootstrap_parity_with_linux() -> None:
    root = Path(__file__).resolve().parents[1]
    sh = (root / "scripts" / "bootstrap_full_stack.sh").read_text(encoding="utf-8")
    ps1 = (root / "scripts" / "bootstrap_full_stack.ps1").read_text(encoding="utf-8")
    assert "SKIP_ADMIN_BOOTSTRAP" in ps1
    assert "BLACK_ONYX_ADMIN_EMAIL" in ps1
    assert "Smoke checks" in ps1
    assert "smoke_malware_lab.py" in ps1
    for key in (
        "SECURITY_SESSIONS_HOST_ROOT",
        "SECURITY_SANDBOX_IMAGE",
        "TOOLBOX_BASE_IMAGE",
        "BLACK_ONYX_DATABASE_URL",
    ):
        assert key in sh and key in ps1


def test_full_stack_bootstrap_creates_databases_then_migrates_before_start() -> None:
    root = Path(__file__).resolve().parents[1]
    script = (root / "scripts" / "bootstrap_full_stack.sh").read_text(encoding="utf-8")

    create_at = script.index("ensure_postgres_databases.py")
    migrate_at = script.index("migrate_sqlite_to_postgres.py")
    start_at = script.index('"${compose[@]}" up -d --build')

    assert create_at < migrate_at < start_at
    assert "SECURITY_SESSIONS_HOST_ROOT" in script
    assert ".security-sessions" in script


def test_windows_bootstrap_creates_databases_then_migrates_before_start() -> None:
    root = Path(__file__).resolve().parents[1]
    script = (root / "scripts" / "bootstrap_full_stack.ps1").read_text(encoding="utf-8")

    create_at = script.index("ensure_postgres_databases.py")
    migrate_at = script.index("migrate_sqlite_to_postgres.py")
    start_at = script.index("up -d --build")

    assert create_at < migrate_at < start_at
    assert "SECURITY_SESSIONS_HOST_ROOT" in script
    assert "SECURITY_SANDBOX_IMAGE" in script


def test_security_gateway_image_runs_alembic_before_server() -> None:
    root = Path(__file__).resolve().parents[1]
    dockerfile = (
        root / "services" / "security-gateway" / "Dockerfile"
    ).read_text(encoding="utf-8")

    assert "COPY --from=builder /app/alembic /app/alembic" in dockerfile
    assert "security_gateway.startup" in dockerfile


def test_web_image_runs_alembic_before_server() -> None:
    root = Path(__file__).resolve().parents[1]
    dockerfile = (root / "Dockerfile").read_text(encoding="utf-8")
    compose = (root / "docker-compose.yml").read_text(encoding="utf-8")
    starter = (root / "scripts" / "start_black_onyx_web.py").read_text(encoding="utf-8")

    assert "scripts/start_black_onyx_web.py" in dockerfile
    assert "scripts/start_black_onyx_web.py" in compose
    assert "ensure_tip_schema_after_migrate" in starter
    assert "ensure_auth_schema_after_migrate" in starter
    assert "_ensure_tip_postgres_schema" in starter
    assert "ux_users_email_lower" in starter


def test_etl_rejects_incomplete_row_counts() -> None:
    from scripts.migrate_sqlite_to_postgres import verify_migrated_counts

    with pytest.raises(RuntimeError, match="row-count verification failed"):
        verify_migrated_counts(
            "tip",
            {"feeds.sqlite:feeds": 3},
            {"feeds": 2},
        )


def test_platform_alembic_version_table_stays_in_public_schema() -> None:
    root = Path(__file__).resolve().parents[1]
    env_module = (root / "alembic" / "env.py").read_text(encoding="utf-8")

    assert env_module.count('version_table_schema="public"') == 2


def test_security_gateway_migration_has_cutover_marker_table() -> None:
    root = Path(__file__).resolve().parents[1]
    migration = (
        root
        / "services"
        / "security-gateway"
        / "alembic"
        / "versions"
        / "0001_gateway_state.py"
    ).read_text(encoding="utf-8")

    assert '"platform_cutover"' in migration


def test_etl_skips_a_domain_after_its_cutover_marker(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from scripts import migrate_sqlite_to_postgres as migration

    monkeypatch.setattr(migration, "_cutover_completed", lambda _url, _domain: True)

    assert migration.migrate_auth(tmp_path, "postgresql://unused") == {
        "skipped": True,
        "reason": "auth cutover already completed",
    }


def test_web_startup_refuses_without_database_url(monkeypatch: pytest.MonkeyPatch) -> None:
    from scripts import start_black_onyx_web

    monkeypatch.delenv("BLACK_ONYX_DATABASE_URL", raising=False)
    with pytest.raises(SystemExit, match="BLACK_ONYX_DATABASE_URL is required"):
        start_black_onyx_web.require_database_url()
    monkeypatch.setenv("BLACK_ONYX_DATABASE_URL", "postgresql+psycopg://u:p@db/black_onyx")
    start_black_onyx_web.require_database_url()
