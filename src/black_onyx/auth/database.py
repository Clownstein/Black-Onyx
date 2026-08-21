"""Canonical SQLite state database and migrations."""

from __future__ import annotations

import logging
import shutil
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


SCHEMA_VERSION = 9
CANONICAL_STATE_DB = "black_onyx.sqlite"
LEGACY_STATE_DBS = ("defenders_chat.sqlite",)
logger = logging.getLogger(__name__)


def _sqlite_user_count(db_path: Path) -> int:
    if not db_path.exists() or db_path.stat().st_size <= 0:
        return 0
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        try:
            tables = {
                str(row[0])
                for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
            }
            if "users" not in tables:
                return 0
            return int(conn.execute("SELECT COUNT(*) FROM users").fetchone()[0])
        finally:
            conn.close()
    except sqlite3.Error:
        return 0


def adopt_legacy_state_database(state_dir: Path, canonical: Path) -> None:
    """Copy DefenderChat state into black_onyx.sqlite when the new DB has no users."""
    if _sqlite_user_count(canonical) > 0:
        return
    for name in LEGACY_STATE_DBS:
        legacy = state_dir / name
        if _sqlite_user_count(legacy) <= 0:
            continue
        for side in (canonical, Path(f"{canonical}-wal"), Path(f"{canonical}-shm")):
            if side.exists():
                side.unlink()
        shutil.copy2(legacy, canonical)
        # Ensure the process user can open WAL mode after adopting a root-copied file.
        try:
            canonical.chmod(0o664)
        except OSError:
            pass
        logger.info("Adopted legacy state database %s as %s", legacy.name, canonical.name)
        return


class StateDatabase:
    def __init__(self, state_dir: str) -> None:
        path = Path(state_dir)
        path.mkdir(parents=True, exist_ok=True)
        self.path = path / CANONICAL_STATE_DB
        adopt_legacy_state_database(path, self.path)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False, timeout=30)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.execute("PRAGMA busy_timeout=30000")
        self._migrate()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            try:
                yield self._conn
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise

    def _migrate(self) -> None:
        with self.transaction() as db:
            db.execute("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)")
            row = db.execute("SELECT version FROM schema_version LIMIT 1").fetchone()
            version = int(row["version"]) if row else 0
            if version < 1:
                db.executescript("""
                CREATE TABLE IF NOT EXISTS users (
                    user_id TEXT PRIMARY KEY,
                    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                    display_name TEXT NOT NULL DEFAULT '',
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL CHECK(role IN ('admin','analyst','viewer')),
                    active INTEGER NOT NULL DEFAULT 1,
                    mfa_secret_encrypted TEXT,
                    mfa_enabled INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS auth_sessions (
                    session_hash TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
                    csrf_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    last_seen_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    ip_address TEXT,
                    user_agent TEXT
                );
                CREATE TABLE IF NOT EXISTS invitations (
                    invitation_id TEXT PRIMARY KEY,
                    token_hash TEXT NOT NULL UNIQUE,
                    email TEXT NOT NULL COLLATE NOCASE,
                    role TEXT NOT NULL,
                    created_by TEXT NOT NULL REFERENCES users(user_id),
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    used_at TEXT
                );
                CREATE TABLE IF NOT EXISTS password_resets (
                    reset_id TEXT PRIMARY KEY,
                    token_hash TEXT NOT NULL UNIQUE,
                    user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    used_at TEXT
                );
                CREATE TABLE IF NOT EXISTS recovery_codes (
                    user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
                    code_hash TEXT NOT NULL,
                    used_at TEXT,
                    PRIMARY KEY(user_id, code_hash)
                );
                CREATE TABLE IF NOT EXISTS audit_events (
                    event_id TEXT PRIMARY KEY,
                    actor_user_id TEXT REFERENCES users(user_id),
                    action TEXT NOT NULL,
                    target_type TEXT,
                    target_id TEXT,
                    ip_address TEXT,
                    detail TEXT,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_sessions_user ON auth_sessions(user_id);
                CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_events(created_at);
                """)
                db.execute("DELETE FROM schema_version")
                db.execute("INSERT INTO schema_version(version) VALUES (1)")
                version = 1
            if version < 2:
                db.executescript("""
                CREATE TABLE IF NOT EXISTS jobs (
                    job_id TEXT PRIMARY KEY,
                    owner_user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
                    job_type TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN (
                        'queued','running','stopping','stopped','completed','failed'
                    )),
                    detail TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_jobs_owner_updated
                    ON jobs(owner_user_id, updated_at DESC);
                """)
                db.execute("UPDATE schema_version SET version=2")
                version = 2
            if version < 3:
                db.executescript("""
                CREATE TABLE IF NOT EXISTS legacy_migrations (
                    migration_id TEXT PRIMARY KEY,
                    applied_at TEXT NOT NULL,
                    backup_dir TEXT NOT NULL,
                    detail TEXT NOT NULL DEFAULT '{}'
                );
                """)
                db.execute("UPDATE schema_version SET version=3")
                version = 3
            if version < 4:
                db.executescript("""
                CREATE TABLE IF NOT EXISTS reports (
                    report_id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    format TEXT NOT NULL CHECK(format IN ('markdown','html','pdf')),
                    relative_path TEXT NOT NULL,
                    created_by TEXT NOT NULL REFERENCES users(user_id),
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_reports_created ON reports(created_at DESC);
                """)
                db.execute("UPDATE schema_version SET version=4")
                version = 4
            if version < 5:
                db.executescript("""
                CREATE TABLE IF NOT EXISTS runtime_settings (
                    settings_id TEXT PRIMARY KEY,
                    config_json TEXT NOT NULL DEFAULT '{}',
                    secrets_encrypted TEXT,
                    updated_by TEXT REFERENCES users(user_id),
                    updated_at TEXT NOT NULL
                );
                """)
                db.execute("UPDATE schema_version SET version=5")
                version = 5
            if version < 6:
                db.executescript("""
                CREATE TABLE IF NOT EXISTS user_sites (
                    site_id TEXT PRIMARY KEY,
                    owner_user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
                    name TEXT NOT NULL,
                    url TEXT NOT NULL,
                    login_url TEXT,
                    section TEXT NOT NULL DEFAULT 'sites'
                        CHECK(section IN ('investigate','intelligence','operations','control','sites')),
                    tags TEXT NOT NULL DEFAULT '[]',
                    open_mode TEXT NOT NULL DEFAULT 'new_tab'
                        CHECK(open_mode IN ('new_tab','embedded','launcher')),
                    favicon_relative_path TEXT,
                    credential_id TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_sites_owner
                    ON user_sites(owner_user_id, updated_at DESC);
                """)
                db.execute("UPDATE schema_version SET version=6")
                version = 6
            if version < 7:
                db.executescript("""
                CREATE TABLE IF NOT EXISTS stored_credentials (
                    credential_id TEXT PRIMARY KEY,
                    owner_user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
                    site_id TEXT NOT NULL REFERENCES user_sites(site_id) ON DELETE CASCADE,
                    username_encrypted TEXT NOT NULL,
                    secret_encrypted TEXT NOT NULL,
                    notes_encrypted TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    last_accessed_at TEXT
                );
                CREATE UNIQUE INDEX IF NOT EXISTS idx_credentials_site
                    ON stored_credentials(site_id);
                CREATE INDEX IF NOT EXISTS idx_credentials_owner
                    ON stored_credentials(owner_user_id);
                """)
                db.execute("UPDATE schema_version SET version=7")
                version = 7
            if version < 8:
                # NULL = never probed; 0/1 = the last probe_frameable() result.
                # Separate ALTER TABLE statements because SQLite's ALTER TABLE
                # only supports one column-add per statement.
                db.executescript("""
                ALTER TABLE user_sites ADD COLUMN frameable INTEGER;
                ALTER TABLE user_sites ADD COLUMN frameable_checked_at TEXT;
                ALTER TABLE user_sites ADD COLUMN frameable_error TEXT;
                """)
                db.execute("UPDATE schema_version SET version=8")
                version = 8
            if version < 9:
                db.executescript("""
                CREATE TABLE IF NOT EXISTS analytics_views (
                    view_id TEXT PRIMARY KEY,
                    owner_user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
                    name TEXT NOT NULL,
                    range_key TEXT NOT NULL DEFAULT '30d',
                    tab_key TEXT NOT NULL DEFAULT 'volume',
                    role_default TEXT CHECK(role_default IS NULL OR role_default IN ('admin','analyst','viewer')),
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(owner_user_id, name)
                );
                CREATE INDEX IF NOT EXISTS idx_analytics_views_owner
                    ON analytics_views(owner_user_id, updated_at DESC);
                CREATE INDEX IF NOT EXISTS idx_analytics_views_role
                    ON analytics_views(role_default);
                """)
                # Optional template tag for intel vs ops_digest library filtering.
                try:
                    db.execute(
                        "ALTER TABLE reports ADD COLUMN template TEXT "
                        "NOT NULL DEFAULT 'intel'"
                    )
                except sqlite3.OperationalError:
                    pass
                db.execute("UPDATE schema_version SET version=?", (SCHEMA_VERSION,))

    def close(self) -> None:
        with self._lock:
            self._conn.close()
