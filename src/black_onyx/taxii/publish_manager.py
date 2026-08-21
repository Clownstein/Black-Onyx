"""TAXII 2.1 outbound publish manager — collections, STIX objects, API keys."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import secrets
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class TaxiiPublishManager:
    """SQLite-backed TAXII 2.1 collection and object store for outbound sharing."""

    def __init__(self, persist_dir: str | None = None) -> None:
        self._persist_dir = Path(persist_dir) if persist_dir else None
        self._lock = threading.Lock()
        db_path = ":memory:"
        if self._persist_dir:
            self._persist_dir.mkdir(parents=True, exist_ok=True)
            db_path = str(self._persist_dir / "taxii_publish.sqlite")
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_db()

    def _init_db(self) -> None:
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS collections (
                collection_id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT,
                enabled INTEGER NOT NULL DEFAULT 1
            );
            CREATE TABLE IF NOT EXISTS objects (
                collection_id TEXT NOT NULL,
                object_id TEXT NOT NULL,
                stix_json TEXT NOT NULL,
                created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (collection_id, object_id),
                FOREIGN KEY (collection_id) REFERENCES collections(collection_id)
            );
            CREATE INDEX IF NOT EXISTS idx_objects_collection
                ON objects(collection_id, created);
            CREATE TABLE IF NOT EXISTS api_keys (
                key_id TEXT PRIMARY KEY,
                token_hash TEXT NOT NULL UNIQUE,
                token_prefix TEXT NOT NULL,
                name TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1
            );
            CREATE INDEX IF NOT EXISTS idx_taxii_keys_hash ON api_keys(token_hash);
            CREATE TABLE IF NOT EXISTS audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_id TEXT,
                action TEXT NOT NULL,
                detail TEXT,
                at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """
        )
        self._migrate_objects_primary_key()
        self._conn.commit()

    def _migrate_objects_primary_key(self) -> None:
        """Upgrade legacy single-column object_id PK to composite (collection, object)."""
        row = self._conn.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='objects'"
        ).fetchone()
        if row is None or not row["sql"]:
            return
        sql = row["sql"].replace("\n", " ")
        if "PRIMARY KEY (collection_id, object_id)" in sql:
            return
        # Legacy schema used object_id as the sole primary key.
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS objects_v2 (
                collection_id TEXT NOT NULL,
                object_id TEXT NOT NULL,
                stix_json TEXT NOT NULL,
                created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (collection_id, object_id),
                FOREIGN KEY (collection_id) REFERENCES collections(collection_id)
            );
            INSERT OR IGNORE INTO objects_v2 (collection_id, object_id, stix_json, created)
            SELECT collection_id, object_id, stix_json, created FROM objects;
            DROP TABLE objects;
            ALTER TABLE objects_v2 RENAME TO objects;
            CREATE INDEX IF NOT EXISTS idx_objects_collection
                ON objects(collection_id, created);
            """
        )

    @staticmethod
    def _hash_token(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def create_collection(
        self, title: str, description: str = "", enabled: bool = True,
    ) -> dict[str, Any]:
        collection_id = str(uuid.uuid4())
        with self._lock:
            self._conn.execute(
                "INSERT INTO collections (collection_id, title, description, enabled) VALUES (?, ?, ?, ?)",
                (collection_id, title.strip(), description.strip(), 1 if enabled else 0),
            )
            self._conn.commit()
        return {
            "collection_id": collection_id,
            "title": title.strip(),
            "description": description.strip(),
            "enabled": enabled,
        }

    def list_collections(self, enabled_only: bool = False) -> list[dict[str, Any]]:
        if enabled_only:
            rows = self._conn.execute(
                "SELECT * FROM collections WHERE enabled = 1 ORDER BY title"
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM collections ORDER BY title"
            ).fetchall()
        return [
            {
                "collection_id": r["collection_id"],
                "title": r["title"],
                "description": r["description"] or "",
                "enabled": bool(r["enabled"]),
            }
            for r in rows
        ]

    def get_collection(self, collection_id: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT * FROM collections WHERE collection_id = ?", (collection_id,),
        ).fetchone()
        if not row:
            return None
        return {
            "collection_id": row["collection_id"],
            "title": row["title"],
            "description": row["description"] or "",
            "enabled": bool(row["enabled"]),
        }

    def set_collection_enabled(self, collection_id: str, enabled: bool) -> bool:
        with self._lock:
            cur = self._conn.execute(
                "UPDATE collections SET enabled = ? WHERE collection_id = ?",
                (1 if enabled else 0, collection_id),
            )
            self._conn.commit()
            return cur.rowcount > 0

    def publish_stix_objects(
        self, collection_id: str, objects: list[dict[str, Any]],
    ) -> dict[str, Any]:
        collection = self.get_collection(collection_id)
        if collection is None:
            raise ValueError("Collection not found")
        if not collection["enabled"]:
            raise ValueError("Collection is disabled")

        now = datetime.now(timezone.utc).isoformat()
        stored = 0
        with self._lock:
            for obj in objects:
                if not isinstance(obj, dict):
                    continue
                object_id = str(obj.get("id") or f"x-defenders--{uuid.uuid4()}")
                self._conn.execute(
                    "INSERT OR REPLACE INTO objects (collection_id, object_id, stix_json, created) "
                    "VALUES (?, ?, ?, ?)",
                    (collection_id, object_id, json.dumps(obj, separators=(",", ":")), now),
                )
                stored += 1
            self._conn.commit()
        return {
            "collection_id": collection_id,
            "objects_stored": stored,
            "created": now,
        }

    def list_objects(
        self,
        collection_id: str,
        limit: int = 100,
        added_after: str | None = None,
    ) -> list[dict[str, Any]]:
        limit = max(1, min(int(limit), 1000))
        if added_after:
            rows = self._conn.execute(
                "SELECT stix_json, created FROM objects WHERE collection_id = ? AND created > ? "
                "ORDER BY created ASC LIMIT ?",
                (collection_id, added_after, limit),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT stix_json, created FROM objects WHERE collection_id = ? "
                "ORDER BY created ASC LIMIT ?",
                (collection_id, limit),
            ).fetchall()
        results: list[dict[str, Any]] = []
        for row in rows:
            try:
                obj = json.loads(row["stix_json"])
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                results.append(obj)
        return results

    def create_api_key(self, name: str) -> dict[str, Any]:
        """Create an API key; plaintext token is returned once."""
        key_id = str(uuid.uuid4())
        token = secrets.token_urlsafe(32)
        token_hash = self._hash_token(token)
        prefix = token[:8]
        with self._lock:
            self._conn.execute(
                "INSERT INTO api_keys (key_id, token_hash, token_prefix, name, enabled) "
                "VALUES (?, ?, ?, ?, 1)",
                (key_id, token_hash, prefix, name.strip()),
            )
            self._conn.commit()
        self.audit_log(key_id, "key.create", name.strip())
        return {
            "key_id": key_id,
            "name": name.strip(),
            "token": token,
            "token_prefix": prefix,
            "enabled": True,
        }

    def list_api_keys(self) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT key_id, name, token_prefix, enabled FROM api_keys ORDER BY name"
        ).fetchall()
        return [
            {
                "key_id": r["key_id"],
                "name": r["name"],
                "token_prefix": r["token_prefix"],
                "enabled": bool(r["enabled"]),
            }
            for r in rows
        ]

    def set_api_key_enabled(self, key_id: str, enabled: bool) -> bool:
        with self._lock:
            cur = self._conn.execute(
                "UPDATE api_keys SET enabled = ? WHERE key_id = ?",
                (1 if enabled else 0, key_id),
            )
            self._conn.commit()
            return cur.rowcount > 0

    def delete_api_key(self, key_id: str) -> bool:
        with self._lock:
            cur = self._conn.execute("DELETE FROM api_keys WHERE key_id = ?", (key_id,))
            self._conn.commit()
            return cur.rowcount > 0

    def authenticate_key(self, token: str) -> dict[str, Any] | None:
        if not token or len(token) > 256:
            return None
        token_hash = self._hash_token(token)
        row = self._conn.execute(
            "SELECT key_id, name, enabled, token_hash FROM api_keys WHERE token_hash = ?",
            (token_hash,),
        ).fetchone()
        if row is None:
            return None
        if not hmac.compare_digest(row["token_hash"], token_hash):
            return None
        if not row["enabled"]:
            return None
        return {"key_id": row["key_id"], "name": row["name"]}

    def audit_log(self, key_id: str | None, action: str, detail: str = "") -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO audit (key_id, action, detail, at) VALUES (?, ?, ?, ?)",
                (
                    key_id,
                    action,
                    detail,
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
            self._conn.commit()

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None
