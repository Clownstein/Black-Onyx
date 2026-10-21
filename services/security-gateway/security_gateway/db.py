"""Security gateway durable state Postgres or legacy SQLite files."""

from __future__ import annotations

import os
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.pool import NullPool

_engine_lock = threading.Lock()
_engine: Engine | None = None


def _postgres_url() -> str | None:
    url = (os.environ.get("SECURITY_GATEWAY_DATABASE_URL") or "").strip()
    return url or None


def _sqlite_approval_path() -> Path:
    return Path(os.environ.get("SECURITY_APPROVAL_DB", "/app/state/approvals.db"))


def _sqlite_challenge_path() -> Path:
    return Path(os.environ.get("SECURITY_CHALLENGE_DB", "/app/state/challenges.sqlite3"))


def get_engine() -> Engine:
    global _engine
    url = _postgres_url()
    if not url:
        raise RuntimeError("SECURITY_GATEWAY_DATABASE_URL is not configured")
    with _engine_lock:
        if _engine is None:
            _engine = create_engine(url, pool_pre_ping=True, poolclass=NullPool)
        return _engine


def reset_gateway_engine_for_tests() -> None:
    global _engine
    with _engine_lock:
        if _engine is not None:
            _engine.dispose()
        _engine = None


@contextmanager
def gateway_connection() -> Iterator[Any]:
    url = _postgres_url()
    if url:
        engine = get_engine()
        with engine.begin() as conn:
            yield _PostgresGatewayConnection(conn)
        return
    path = _sqlite_approval_path()
    if not path.parent.is_dir():
        raise RuntimeError("Security approval state directory is unavailable")
    connection = sqlite3.connect(path, timeout=10, isolation_level=None)
    connection.execute("PRAGMA busy_timeout=10000")
    try:
        yield connection
    finally:
        connection.close()


@contextmanager
def challenge_connection() -> Iterator[Any]:
    url = _postgres_url()
    if url:
        engine = get_engine()
        with engine.begin() as conn:
            yield _PostgresGatewayConnection(conn)
        return
    path = _sqlite_challenge_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=5.0)
    connection.execute("PRAGMA busy_timeout=5000")
    try:
        yield connection
    finally:
        connection.close()


class _PostgresGatewayConnection:
    def __init__(self, conn: Any) -> None:
        self._conn = conn

    def execute(self, sql: str, params: tuple[Any, ...] | None = None) -> Any:
        adapted = sql.replace("?", "%s")
        if adapted.upper().startswith("INSERT OR IGNORE"):
            adapted = adapted.replace("INSERT OR IGNORE", "INSERT", 1)
            if " ON CONFLICT" not in adapted.upper():
                adapted = f"{adapted} ON CONFLICT DO NOTHING"
        if params:
            return self._conn.exec_driver_sql(adapted, params)
        return self._conn.exec_driver_sql(adapted)

    def commit(self) -> None:
        pass

    def rollback(self) -> None:
        self._conn.rollback()


def ensure_gateway_schema() -> None:
    url = _postgres_url()
    if not url:
        return
    engine = get_engine()
    with engine.begin() as conn:
        row = conn.execute(
            text(
                "SELECT 1 FROM information_schema.tables "
                "WHERE table_schema = 'public' AND table_name = 'approvals' LIMIT 1"
            )
        ).fetchone()
        if row is None:
            raise RuntimeError(
                "security-gateway schema is not migrated. Run alembic upgrade head in services/security-gateway."
            )


def gateway_ready() -> bool:
    try:
        if _postgres_url():
            ensure_gateway_schema()
            with gateway_connection() as db:
                db.execute("SELECT 1 FROM approvals LIMIT 1")
            with challenge_connection() as db:
                db.execute("SELECT 1 FROM challenge_solves LIMIT 1")
            return True
        with gateway_connection() as db:
            db.execute("SELECT 1 FROM approvals LIMIT 1")
        with challenge_connection() as db:
            db.execute("SELECT 1 FROM challenge_solves LIMIT 1")
        return True
    except Exception:
        return False


def utc_epoch() -> int:
    return int(time.time())
