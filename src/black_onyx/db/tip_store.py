"""Shared TIP persistence one Postgres ``tip`` schema or per-feature SQLite files."""

from __future__ import annotations

import sqlite3
import threading
from pathlib import Path
from typing import Any

from sqlalchemy import text
from sqlalchemy.engine import Engine

from black_onyx.db.config import black_onyx_database_url, production_requires_postgres
from black_onyx.db.sql_compat import (
    PostgresCompatConnection,
    REPLACE_CONFLICT_TARGETS,
    create_postgres_compat_engine,
)

_pool_lock = threading.Lock()
_tip_engine = None
_tip_compat: PostgresCompatConnection | None = None

# Core TIP tables that must exist before the web process serves traffic.
_TIP_REQUIRED_TABLES: tuple[str, ...] = tuple(
    sorted({"feeds", *REPLACE_CONFLICT_TARGETS.keys()})
)


def _ensure_tip_postgres_schema(engine: Engine) -> None:
    """Fail closed when the tip schema has not been migrated yet."""
    with engine.connect() as conn:
        conn.execute(text('SET search_path TO "tip"'))
        missing: list[str] = []
        for table in _TIP_REQUIRED_TABLES:
            try:
                conn.execute(text(f'SELECT 1 FROM "{table}" LIMIT 1'))
            except Exception:
                missing.append(table)
        if missing:
            raise RuntimeError(
                "tip schema is not migrated. Missing tables: "
                + ", ".join(missing)
                + ". Run `alembic upgrade head` before startup."
            )


class TipStore:
    """Process-wide handle for the unified TIP Postgres schema."""

    def __init__(self, database_url: str) -> None:
        self.database_url = database_url
        self._engine = create_postgres_compat_engine(database_url, "tip")
        _ensure_tip_postgres_schema(self._engine)
        self._compat = PostgresCompatConnection(self._engine, "tip")

    @property
    def connection(self) -> PostgresCompatConnection:
        return self._compat

    def close(self) -> None:
        self._compat.close()
        self._engine.dispose()


def _shared_tip_compat() -> PostgresCompatConnection:
    global _tip_engine, _tip_compat
    url = black_onyx_database_url()
    if not url:
        raise RuntimeError("BLACK_ONYX_DATABASE_URL is not configured")
    with _pool_lock:
        if _tip_compat is None:
            _tip_engine = create_postgres_compat_engine(url, "tip")
            _ensure_tip_postgres_schema(_tip_engine)
            _tip_compat = PostgresCompatConnection(_tip_engine, "tip")
        return _tip_compat


def connect_tip_store(
    persist_dir: Path | None,
    legacy_filename: str,
    *,
    production: bool | None = None,
) -> Any:
    """Return sqlite3.Connection or PostgresCompatConnection for TIP managers."""
    url = black_onyx_database_url()
    require_url = production if production is not None else production_requires_postgres()
    if require_url and not url:
        raise RuntimeError(
            "BLACK_ONYX_DATABASE_URL is required in production (no SQLite fallback)"
        )
    if url:
        return _shared_tip_compat()
    db_path = ":memory:"
    if persist_dir is not None:
        persist_dir.mkdir(parents=True, exist_ok=True)
        db_path = str(persist_dir / legacy_filename)
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def tip_store_for_url(database_url: str) -> TipStore:
    return TipStore(database_url)


def reset_tip_store_cache_for_tests() -> None:
    global _tip_engine, _tip_compat
    with _pool_lock:
        if _tip_compat is not None:
            _tip_compat.close()
        if _tip_engine is not None:
            _tip_engine.dispose()
        _tip_engine = None
        _tip_compat = None
