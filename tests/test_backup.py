"""Tests for admin backup/restore of SQLite state (and inventory without Qdrant)."""

from __future__ import annotations

import zipfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from black_onyx.ops.backup_manager import MANIFEST_NAME, BackupManager, _libpq_target


def test_libpq_target_strips_driver_and_moves_password_to_env() -> None:
    url, env = _libpq_target("postgresql+psycopg://anomaly:s%40cret@postgres:5432/black_onyx")
    assert url == "postgresql://anomaly@postgres:5432/black_onyx"
    assert env["PGPASSWORD"] == "s@cret"
    url, env = _libpq_target("postgresql://anomaly@localhost/db")
    assert url == "postgresql://anomaly@localhost/db"


def test_backup_manager_sqlite_roundtrip(tmp_path: Path):
    state = tmp_path / "state"
    state.mkdir()
    import sqlite3
    db = state / "watchlists.sqlite"
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, name TEXT)")
    conn.execute("INSERT INTO t(name) VALUES ('alpha')")
    conn.commit()
    conn.close()
    (state / "sla_policy.json").write_text('{"critical": 4}', encoding="utf-8")

    mgr = BackupManager(state, qdrant_store=None)
    created = mgr.create_backup(include_qdrant=False, label="unit")
    assert created["backup_id"]
    archive = Path(created["path"])
    assert archive.is_file()
    with zipfile.ZipFile(archive) as zf:
        assert MANIFEST_NAME in zf.namelist()
        assert "sqlite/watchlists.sqlite" in zf.namelist()

    conn = sqlite3.connect(db)
    conn.execute("UPDATE t SET name='beta'")
    conn.commit()
    conn.close()

    restored = mgr.restore_backup(created["backup_id"], include_qdrant=False, include_sqlite=True)
    assert "watchlists.sqlite" in restored["restored_sqlite"]
    conn = sqlite3.connect(db)
    name = conn.execute("SELECT name FROM t").fetchone()[0]
    conn.close()
    assert name == "alpha"


def test_qdrant_restore_failure_rolls_back_and_preserves_sqlite(tmp_path: Path):
    import sqlite3

    class FakeQdrant:
        value = b"vector-alpha"
        fail_once = False

        def list_collections(self):
            return [{"name": "evidence"}]

        def create_and_download_snapshot(self, collection, destination):
            assert collection == "evidence"
            destination.write_bytes(self.value)
            return {"collection": collection}

        def upload_and_recover_snapshot(self, collection, snapshot):
            self.value = snapshot.read_bytes()
            if self.fail_once:
                self.fail_once = False
                raise RuntimeError("vector restore failed after mutation")
            return {"collection": collection}

    state = tmp_path / "state"
    state.mkdir()
    db_path = state / "watchlists.sqlite"
    with sqlite3.connect(db_path) as db:
        db.execute("CREATE TABLE t (name TEXT)")
        db.execute("INSERT INTO t VALUES ('alpha')")
    qdrant = FakeQdrant()
    manager = BackupManager(state, qdrant_store=qdrant)
    backup_id = manager.create_backup(include_qdrant=True)["backup_id"]
    with sqlite3.connect(db_path) as db:
        db.execute("UPDATE t SET name='beta'")
    qdrant.value = b"vector-beta"
    qdrant.fail_once = True

    with pytest.raises(RuntimeError, match="vector restore failed"):
        manager.restore_backup(backup_id)
    with sqlite3.connect(db_path) as db:
        assert db.execute("SELECT name FROM t").fetchone()[0] == "beta"
    assert qdrant.value == b"vector-beta"

    manager.restore_backup(backup_id)
    with sqlite3.connect(db_path) as db:
        assert db.execute("SELECT name FROM t").fetchone()[0] == "alpha"
    assert qdrant.value == b"vector-alpha"


@pytest.fixture
def authenticated_backup(tmp_path, monkeypatch):
    monkeypatch.setenv("QDRANT_STORAGE__STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("QDRANT_SECURITY__EXTERNAL_URL", "http://testserver")
    monkeypatch.setenv("BLACK_ONYX_AUTH_SECRET", "test-secret-that-is-long-and-random")
    monkeypatch.setenv("QDRANT_FEEDS__ENABLED", "false")
    monkeypatch.setenv("QDRANT_CONNECTORS__ENABLED", "false")
    from black_onyx.api.app import create_app
    from black_onyx.api.service import AppService
    from black_onyx.auth.context import get_auth_service
    from black_onyx.config import get_settings

    if AppService._instance is not None:
        AppService._instance._settings_store.database.close()
    AppService._instance = None
    AppService._initialized = False
    get_settings.cache_clear()
    get_auth_service.cache_clear()
    auth = get_auth_service()
    auth.bootstrap_admin("admin@example.com", "correct horse battery staple", "Admin")
    monkeypatch.setattr(AppService, "ensure_default_collections", lambda self: [], raising=False)
    monkeypatch.setattr(AppService, "start_background_schedulers", lambda self: None, raising=False)
    monkeypatch.setattr(AppService, "qdrant_store", property(lambda self: MagicMock()), raising=False)

    with TestClient(create_app(), raise_server_exceptions=False) as client:
        login = client.post(
            "/api/v1/auth/login",
            headers={"Origin": "http://testserver"},
            json={"email": "admin@example.com", "password": "correct horse battery staple"},
        )
        assert login.status_code == 200
        client.headers.update({
            "Origin": "http://testserver",
            "X-CSRF-Token": login.json()["csrf_token"],
        })
        yield client
    get_auth_service.cache_clear()
    get_settings.cache_clear()
    if AppService._instance is not None:
        AppService._instance._settings_store.database.close()
    AppService._instance = None
    AppService._initialized = False


def test_backup_api_create_list_download(authenticated_backup: TestClient):
    inventory = authenticated_backup.get("/api/v1/admin/backup/inventory")
    assert inventory.status_code == 200, inventory.text
    assert "sqlite" in inventory.json()

    created = authenticated_backup.post(
        "/api/v1/admin/backup/create",
        json={"include_qdrant": False, "label": "api"},
    )
    assert created.status_code == 200, created.text
    backup_id = created.json()["backup_id"]

    listed = authenticated_backup.get("/api/v1/admin/backup")
    assert listed.status_code == 200
    assert listed.json()["n"] >= 1

    download = authenticated_backup.get(f"/api/v1/admin/backup/{backup_id}/download")
    assert download.status_code == 200
    assert "zip" in download.headers.get("content-type", "")

    deleted = authenticated_backup.delete(f"/api/v1/admin/backup/{backup_id}")
    assert deleted.status_code == 200


def test_backup_retention_prunes_oldest(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    import os
    import time

    state = tmp_path / "state"
    state.mkdir()
    monkeypatch.setenv("BLACK_ONYX_BACKUP_RETENTION", "2")
    mgr = BackupManager(state, qdrant_store=None)
    ids = []
    for index in range(3):
        created = mgr.create_backup(include_qdrant=False, label=f"r{index}")
        # Distinct mtimes so ordering is deterministic on coarse filesystems.
        stamp = time.time() - (10 - index)
        os.utime(created["path"], (stamp, stamp))
        ids.append(created["backup_id"])
    remaining = {item["backup_id"] for item in mgr.list_backups()}
    assert remaining == {ids[1], ids[2]}
    assert created["pruned"] == [ids[0]]


def test_audit_retention_prunes_old_events(tmp_path: Path):
    from datetime import datetime, timedelta, timezone

    from black_onyx.auth.database import StateDatabase

    db = StateDatabase(str(tmp_path))
    old = (datetime.now(timezone.utc) - timedelta(days=400)).isoformat()
    new = datetime.now(timezone.utc).isoformat()
    with db.transaction() as conn:
        conn.execute("INSERT INTO audit_events(event_id,action,created_at) VALUES('old','x',?)", (old,))
        conn.execute("INSERT INTO audit_events(event_id,action,created_at) VALUES('new','x',?)", (new,))
    assert db.prune_audit_events(365) == 1
    assert db.prune_audit_events(0) == 0
    rows = [row[0] for row in db._conn.execute("SELECT event_id FROM audit_events")]
    assert rows == ["new"]
