import sqlite3

from black_onyx.auth.database import StateDatabase
from black_onyx.auth.legacy_migration import MIGRATION_ID, migrate_legacy_state
from black_onyx.auth.service import AuthService
from black_onyx.config import SecurityConfig


def test_bootstrap_backs_up_and_assigns_legacy_chat_sessions(tmp_path, monkeypatch):
    legacy = tmp_path / "chat_sessions.sqlite"
    connection = sqlite3.connect(legacy)
    connection.execute(
        "CREATE TABLE sessions(session_id TEXT PRIMARY KEY,title TEXT,provider TEXT,model TEXT)"
    )
    connection.execute(
        "INSERT INTO sessions VALUES('legacy-chat','Investigation','local','model')"
    )
    connection.commit()
    connection.close()

    monkeypatch.setenv("BLACK_ONYX_AUTH_SECRET", "migration-test-secret")
    database = StateDatabase(str(tmp_path))
    auth = AuthService(database, SecurityConfig(external_url="http://testserver"))
    administrator = auth.bootstrap_admin(
        "admin@example.com", "correct horse battery staple", "Administrator"
    )

    migrated = sqlite3.connect(legacy)
    owner = migrated.execute(
        "SELECT owner_id FROM sessions WHERE session_id='legacy-chat'"
    ).fetchone()[0]
    migrated.close()
    assert owner == administrator.user_id
    backups = list((tmp_path / "legacy-backups").glob("*/chat_sessions.sqlite"))
    assert len(backups) == 1
    backup = sqlite3.connect(backups[0])
    assert "owner_id" not in {
        row[1] for row in backup.execute("PRAGMA table_info(sessions)")
    }
    backup.close()
    marker = database._conn.execute(
        "SELECT 1 FROM legacy_migrations WHERE migration_id=?", (MIGRATION_ID,)
    ).fetchone()
    assert marker is not None

    again = migrate_legacy_state(database, administrator.user_id)
    assert again["assigned_chat_sessions"] == 1
    assert len(list((tmp_path / "legacy-backups").glob("*/chat_sessions.sqlite"))) == 1
