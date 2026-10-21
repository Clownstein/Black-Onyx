"""SQLite-shaped API on SQLAlchemy Postgres connections."""

from __future__ import annotations

import re
import sqlite3
import threading
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from datetime import date, datetime, time
from typing import Any

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.exc import IntegrityError as SAIntegrityError
from sqlalchemy.exc import SQLAlchemyError

_PRAGMA_TABLE_INFO = re.compile(
    r"^PRAGMA\s+table_info\((?P<table>[a-zA-Z_][a-zA-Z0-9_]*)\)\s*$",
    re.IGNORECASE,
)
_SQLITE_MASTER = re.compile(
    r"SELECT\s+name\s+FROM\s+sqlite_master\s+WHERE\s+type\s*=\s*'table'",
    re.IGNORECASE,
)
_INSERT_OR_IGNORE = re.compile(r"^INSERT\s+OR\s+IGNORE\s+", re.IGNORECASE)
_INSERT_OR_REPLACE = re.compile(r"^INSERT\s+OR\s+REPLACE\s+", re.IGNORECASE)
_INSERT_INTO = re.compile(
    r"INSERT\s+INTO\s+(?P<table>[a-zA-Z_][a-zA-Z0-9_]*)\s*\((?P<cols>[^)]+)\)\s*"
    r"VALUES\s*\((?P<vals>[^)]+)\)",
    re.IGNORECASE | re.DOTALL,
)
# Explicit conflict targets for every production INSERT OR REPLACE call site.
# Schema introspection is only a fallback for ad-hoc/temp tables (tests).
REPLACE_CONFLICT_TARGETS: dict[str, tuple[str, ...]] = {
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
_COLLATE_NOCASE_EQ = re.compile(
    r"(?P<left>[A-Za-z_][A-Za-z0-9_.]*)\s*=\s*(?P<right>\?|[A-Za-z_][A-Za-z0-9_.]*)\s+COLLATE\s+NOCASE",
    re.IGNORECASE,
)
_COLLATE_NOCASE = re.compile(r"\s+COLLATE\s+NOCASE", re.IGNORECASE)


def _sqlite_compatible_value(value: Any) -> Any:
    """Preserve sqlite-shaped values for managers that call fromisoformat()."""
    if isinstance(value, datetime):
        return value.isoformat(sep=" ")
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, time):
        return value.isoformat()
    return value


class CompatRow(Mapping[str, Any]):
    __slots__ = ("_keys", "_values")

    def __init__(self, keys: Sequence[str], values: Sequence[Any]) -> None:
        self._keys = list(keys)
        self._values = [_sqlite_compatible_value(value) for value in values]

    def __getitem__(self, key: str | int) -> Any:
        if isinstance(key, int):
            return self._values[key]
        return self._values[self._keys.index(key)]

    def __iter__(self) -> Iterator[Any]:
        # sqlite3.Row iterates values so `a, b = row` unpacks columns, not names.
        return iter(self._values)

    def __len__(self) -> int:
        return len(self._keys)

    def keys(self) -> list[str]:
        return list(self._keys)

    def values(self) -> list[Any]:  # type: ignore[override]
        return list(self._values)

    def items(self) -> list[tuple[str, Any]]:  # type: ignore[override]
        return list(zip(self._keys, self._values, strict=True))


class CompatCursor:
    __slots__ = ("rowcount", "_rows", "_index", "_keys")

    def __init__(self, rowcount: int, keys: Sequence[str], rows: Sequence[Sequence[Any]]) -> None:
        self.rowcount = rowcount
        self._keys = list(keys)
        self._rows = [CompatRow(self._keys, row) for row in rows]
        self._index = 0

    def fetchone(self) -> CompatRow | None:
        if self._index >= len(self._rows):
            return None
        row = self._rows[self._index]
        self._index += 1
        return row

    def __iter__(self) -> Iterator[CompatRow]:
        while self._index < len(self._rows):
            row = self._rows[self._index]
            self._index += 1
            yield row

    def fetchall(self) -> list[CompatRow]:
        rest = self._rows[self._index :]
        self._index = len(self._rows)
        return rest


def _translate_sql(sql: str) -> str:
    stripped = sql.strip().rstrip(";")
    if _SQLITE_MASTER.search(stripped):
        return (
            "SELECT table_name AS name FROM information_schema.tables "
            "WHERE table_schema = current_schema() AND table_type = 'BASE TABLE'"
        )
    if stripped.upper().startswith("PRAGMA "):
        return "SELECT 1 AS ok"
    adapted = stripped
    if _INSERT_OR_IGNORE.match(adapted):
        adapted = _INSERT_OR_IGNORE.sub("INSERT ", adapted)
        if " ON CONFLICT" not in adapted.upper():
            adapted = f"{adapted} ON CONFLICT DO NOTHING"
    adapted = adapted.replace("INTEGER PRIMARY KEY AUTOINCREMENT", "SERIAL PRIMARY KEY")
    adapted = adapted.replace("AUTOINCREMENT", "")
    adapted = _COLLATE_NOCASE_EQ.sub(
        lambda match: f"LOWER({match.group('left')}) = LOWER({match.group('right')})",
        adapted,
    )
    adapted = _COLLATE_NOCASE.sub("", adapted)
    return adapted


def _build_insert_or_replace(sql: str, conflict_cols: Sequence[str]) -> str:
    adapted = _INSERT_OR_REPLACE.sub("INSERT ", sql.strip().rstrip(";"))
    match = _INSERT_INTO.match(adapted)
    if match is None or not conflict_cols:
        raise RuntimeError(
            "INSERT OR REPLACE requires INSERT INTO table(cols) VALUES (...) "
            "and a primary/unique key to target"
        )
    cols = [c.strip() for c in match.group("cols").split(",")]
    assignments = ", ".join(f"{col}=EXCLUDED.{col}" for col in cols)
    conflict = ", ".join(conflict_cols)
    return (
        f"INSERT INTO {match.group('table')} ({match.group('cols')}) "
        f"VALUES ({match.group('vals')}) "
        f"ON CONFLICT ({conflict}) DO UPDATE SET {assignments}"
    )


def _named_params(sql: str, params: Sequence[Any]) -> tuple[str, dict[str, Any]]:
    if "?" not in sql:
        return sql, {}
    parts = sql.split("?")
    bound: dict[str, Any] = {}
    rebuilt: list[str] = []
    for index, part in enumerate(parts[:-1]):
        key = f"p{index}"
        bound[key] = params[index]
        rebuilt.append(f"{part}:{key}")
    rebuilt.append(parts[-1])
    return "".join(rebuilt), bound


class PostgresCompatConnection:
    """Thread-local SQLAlchemy connection with sqlite-like execute()."""

    def __init__(self, engine: Engine, schema: str) -> None:
        self._engine = engine
        self._schema = schema
        self._local = threading.local()

    def _connection(self) -> Connection:
        conn = getattr(self._local, "connection", None)
        if conn is None:
            conn = self._engine.connect()
            conn.execute(text(f'SET search_path TO "{self._schema}"'))
            conn.commit()
            self._local.connection = conn
        return conn

    def _is_dirty(self) -> bool:
        return bool(getattr(self._local, "dirty", False))

    def _set_dirty(self, value: bool) -> None:
        self._local.dirty = value

    def _conflict_target_columns(self, table: str) -> list[str]:
        known = REPLACE_CONFLICT_TARGETS.get(table)
        if known is not None:
            return list(known)
        cache = getattr(self._local, "conflict_cache", None)
        if cache is None:
            cache = {}
            self._local.conflict_cache = cache
        cached = cache.get(table)
        if cached is not None:
            return list(cached)
        conn = self._connection()
        # Include temporary schemas (pg_temp_*) via current_schemas(true).
        pk_rows = conn.execute(
            text(
                "SELECT kcu.column_name AS column_name "
                "FROM information_schema.table_constraints AS tc "
                "JOIN information_schema.key_column_usage AS kcu "
                "  ON tc.constraint_name = kcu.constraint_name "
                " AND tc.table_schema = kcu.table_schema "
                "WHERE tc.table_schema = ANY (current_schemas(true)) "
                "  AND tc.table_name = :table_name "
                "  AND tc.constraint_type = 'PRIMARY KEY' "
                "ORDER BY kcu.ordinal_position"
            ),
            {"table_name": table},
        ).fetchall()
        cols = [str(row[0]) for row in pk_rows]
        if not cols:
            unique_rows = conn.execute(
                text(
                    "SELECT kcu.column_name AS column_name "
                    "FROM information_schema.key_column_usage AS kcu "
                    "WHERE kcu.table_schema = ANY (current_schemas(true)) "
                    "  AND kcu.table_name = :table_name "
                    "  AND kcu.constraint_name = ("
                    "    SELECT tc.constraint_name "
                    "    FROM information_schema.table_constraints AS tc "
                    "    WHERE tc.table_schema = ANY (current_schemas(true)) "
                    "      AND tc.table_name = :table_name "
                    "      AND tc.constraint_type = 'UNIQUE' "
                    "    ORDER BY tc.constraint_name "
                    "    LIMIT 1"
                    "  ) "
                    "ORDER BY kcu.ordinal_position"
                ),
                {"table_name": table},
            ).fetchall()
            cols = [str(row[0]) for row in unique_rows]
        if not cols:
            raise RuntimeError(
                f"INSERT OR REPLACE into {table} needs a PRIMARY KEY or UNIQUE constraint"
            )
        cache[table] = cols
        return list(cols)

    def execute(self, sql: str, params: Sequence[Any] | None = None) -> CompatCursor:
        params = params or ()
        stripped = sql.strip().rstrip(";")
        pragma = _PRAGMA_TABLE_INFO.match(stripped)
        if pragma:
            table = pragma.group("table")
            bind_sql = (
                "SELECT column_name AS name FROM information_schema.columns "
                "WHERE table_schema = current_schema() AND table_name = :table_name "
                "ORDER BY ordinal_position"
            )
            bind_params: dict[str, Any] = {"table_name": table}
        elif _INSERT_OR_REPLACE.match(stripped):
            insert_match = _INSERT_INTO.match(_INSERT_OR_REPLACE.sub("INSERT ", stripped))
            if insert_match is None:
                raise RuntimeError("Unsupported INSERT OR REPLACE shape")
            table = insert_match.group("table")
            conflict_cols = self._conflict_target_columns(table)
            bind_sql = _build_insert_or_replace(stripped, conflict_cols)
            bind_sql, bind_params = _named_params(bind_sql, params)
        else:
            bind_sql = _translate_sql(stripped)
            bind_sql, bind_params = _named_params(bind_sql, params)
        try:
            result = self._connection().execute(text(bind_sql), bind_params)
        except SAIntegrityError as exc:
            self._connection().rollback()
            self._set_dirty(False)
            raise sqlite3.IntegrityError(str(exc)) from exc
        except SQLAlchemyError:
            self._connection().rollback()
            self._set_dirty(False)
            raise
        if result.returns_rows:
            keys = list(result.keys())
            rows = result.fetchall()
            if bind_sql.lstrip().upper().startswith("SELECT") and not self._is_dirty():
                self._connection().commit()
            else:
                self._set_dirty(True)
            return CompatCursor(result.rowcount or 0, keys, rows)
        rowcount = result.rowcount if result.rowcount is not None else 0
        self._set_dirty(True)
        return CompatCursor(rowcount, [], [])

    def executescript(self, script: str) -> None:
        for statement in filter(None, (part.strip() for part in script.split(";"))):
            if statement:
                self.execute(statement)

    def commit(self) -> None:
        self._connection().commit()
        self._set_dirty(False)

    def rollback(self) -> None:
        self._connection().rollback()
        self._set_dirty(False)

    def close(self) -> None:
        conn = getattr(self._local, "connection", None)
        if conn is not None:
            if self._is_dirty():
                conn.rollback()
            conn.close()
            self._local.connection = None
            self._set_dirty(False)


def create_postgres_compat_engine(database_url: str, schema: str) -> Engine:
    engine = create_engine(database_url, pool_pre_ping=True)
    with engine.begin() as conn:
        conn.execute(text(f'CREATE SCHEMA IF NOT EXISTS "{schema}"'))
    return engine


@contextmanager
def postgres_compat_connection(database_url: str, schema: str) -> Iterator[PostgresCompatConnection]:
    engine = create_postgres_compat_engine(database_url, schema)
    wrapper = PostgresCompatConnection(engine, schema)
    try:
        yield wrapper
    finally:
        wrapper.close()
        engine.dispose()
