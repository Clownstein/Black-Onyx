"""Tests for admin backup/restore of SQLite state (and inventory without Qdrant)."""

from __future__ import annotations

import zipfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from black_onyx.ops.backup_manager import MANIFEST_NAME, BackupManager


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
