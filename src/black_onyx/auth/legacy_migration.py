"""Verified, recoverable migration of pre-authentication application state."""

from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from black_onyx.auth.database import StateDatabase

MIGRATION_ID = "legacy-state-v1"


def _verified_backup(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    source_db = sqlite3.connect(source)
    destination_db = sqlite3.connect(destination)
    try:
        source_db.backup(destination_db)
        result = destination_db.execute("PRAGMA integrity_check").fetchone()
        if not result or result[0] != "ok":
            raise RuntimeError(f"Integrity verification failed for {source.name}")
    finally:
        destination_db.close()
        source_db.close()


def migrate_legacy_state(db: StateDatabase, administrator_id: str) -> dict[str, object]:
    """Back up legacy SQLite stores and assign ownerless chats to the bootstrap admin."""
    existing = db._conn.execute(
        "SELECT detail FROM legacy_migrations WHERE migration_id=?", (MIGRATION_ID,)
    ).fetchone()
    if existing:
        return json.loads(existing["detail"])

    state_dir = db.path.parent
    legacy_files = sorted(
        path for path in state_dir.glob("*.sqlite") if path.name != db.path.name
    )
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup_dir = state_dir / "legacy-backups" / stamp
    for source in legacy_files:
        _verified_backup(source, backup_dir / source.name)

    assigned_sessions = 0
    chat_db = state_dir / "chat_sessions.sqlite"
    if chat_db.exists():
        staged = state_dir / f".chat_sessions.{os.getpid()}.migrating.sqlite"
        try:
            _verified_backup(chat_db, staged)
            staged_db = sqlite3.connect(staged)
            try:
                columns = {row[1] for row in staged_db.execute("PRAGMA table_info(sessions)")}
                if "sessions" not in {
                    row[0] for row in staged_db.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    )
                }:
                    raise RuntimeError("Legacy chat database has no sessions table")
                if "owner_id" not in columns:
                    staged_db.execute(
                        "ALTER TABLE sessions ADD COLUMN owner_id TEXT NOT NULL DEFAULT ''"
                    )
                cursor = staged_db.execute(
                    "UPDATE sessions SET owner_id=? WHERE owner_id='' OR owner_id IS NULL",
                    (administrator_id,),
                )
                assigned_sessions = cursor.rowcount
                staged_db.commit()
                if staged_db.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                    raise RuntimeError("Migrated chat database failed integrity verification")
            finally:
                staged_db.close()
            os.replace(staged, chat_db)
        finally:
            staged.unlink(missing_ok=True)

    detail: dict[str, object] = {
        "backed_up_files": [path.name for path in legacy_files],
        "assigned_chat_sessions": assigned_sessions,
    }
    applied_at = datetime.now(timezone.utc).isoformat()
    with db.transaction() as connection:
        connection.execute(
            "INSERT INTO legacy_migrations VALUES(?,?,?,?)",
            (MIGRATION_ID, applied_at, str(backup_dir) if legacy_files else "", json.dumps(detail)),
        )
    return detail
