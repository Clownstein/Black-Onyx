"""Analyst collaboration — annotations, tags, notes, bookmarks on Qdrant points."""

from __future__ import annotations

import logging
import sqlite3
import threading
import uuid
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)


class AnnotationManager:
    """Manages analyst annotations, tags, notes, and bookmarks on Qdrant points.

    Tables: annotations, tags, notes, bookmarks, confidence, status.
    """

    def __init__(self, persist_dir: str | None = None) -> None:
        self._persist_dir = Path(persist_dir) if persist_dir else None
        self._lock = threading.Lock()
        db_path = ":memory:"
        if self._persist_dir:
            self._persist_dir.mkdir(parents=True, exist_ok=True)
            db_path = str(self._persist_dir / "annotations.sqlite")
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_db()

    def _init_db(self) -> None:
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS annotations (
                annotation_id TEXT PRIMARY KEY,
                collection TEXT NOT NULL,
                point_id TEXT NOT NULL,
                author TEXT,
                content TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS tags (
                tag_id TEXT PRIMARY KEY,
                collection TEXT NOT NULL,
                point_id TEXT NOT NULL,
                tag TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS notes (
                note_id TEXT PRIMARY KEY,
                collection TEXT NOT NULL,
                point_id TEXT NOT NULL,
                author TEXT,
                content TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS bookmarks (
                bookmark_id TEXT PRIMARY KEY,
                collection TEXT NOT NULL,
                point_id TEXT NOT NULL,
                user TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS confidence (
                collection TEXT NOT NULL,
                point_id TEXT NOT NULL,
                confidence_score REAL,
                author TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (collection, point_id)
            );
            CREATE TABLE IF NOT EXISTS status (
                collection TEXT NOT NULL,
                point_id TEXT NOT NULL,
                status TEXT,
                author TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (collection, point_id)
            );
            CREATE INDEX IF NOT EXISTS idx_ann_point ON annotations(collection, point_id);
            CREATE INDEX IF NOT EXISTS idx_tags_point ON tags(collection, point_id);
            CREATE INDEX IF NOT EXISTS idx_notes_point ON notes(collection, point_id);
        """)
        self._conn.commit()

    def add_annotation(self, collection: str, point_id: str, author: str, content: str) -> str:
        ann_id = str(uuid.uuid4())
        with self._lock:
            self._conn.execute(
                "INSERT INTO annotations (annotation_id, collection, point_id, author, content) "
                "VALUES (?, ?, ?, ?, ?)",
                (ann_id, collection, point_id, author, content),
            )
            self._conn.commit()
        return ann_id

    def get_annotations(self, collection: str, point_id: str) -> list[dict]:
        rows = self._conn.execute(
            "SELECT * FROM annotations WHERE collection = ? AND point_id = ? ORDER BY created_at DESC",
            (collection, point_id),
        ).fetchall()
        return [dict(r) for r in rows]

    def add_tag(self, collection: str, point_id: str, tag: str) -> None:
        tag_id = str(uuid.uuid4())
        with self._lock:
            self._conn.execute(
                "INSERT INTO tags (tag_id, collection, point_id, tag) VALUES (?, ?, ?, ?)",
                (tag_id, collection, point_id, tag),
            )
            self._conn.commit()

    def remove_tag(self, collection: str, point_id: str, tag: str) -> None:
        with self._lock:
            self._conn.execute(
                "DELETE FROM tags WHERE collection = ? AND point_id = ? AND tag = ?",
                (collection, point_id, tag),
            )
            self._conn.commit()

    def get_tags(self, collection: str, point_id: str) -> list[str]:
        rows = self._conn.execute(
            "SELECT tag FROM tags WHERE collection = ? AND point_id = ?",
            (collection, point_id),
        ).fetchall()
        return [r["tag"] for r in rows]

    def add_note(self, collection: str, point_id: str, author: str, content: str) -> str:
        note_id = str(uuid.uuid4())
        with self._lock:
            self._conn.execute(
                "INSERT INTO notes (note_id, collection, point_id, author, content) "
                "VALUES (?, ?, ?, ?, ?)",
                (note_id, collection, point_id, author, content),
            )
            self._conn.commit()
        return note_id

    def get_notes(self, collection: str, point_id: str) -> list[dict]:
        rows = self._conn.execute(
            "SELECT * FROM notes WHERE collection = ? AND point_id = ? ORDER BY created_at DESC",
            (collection, point_id),
        ).fetchall()
        return [dict(r) for r in rows]

    def toggle_bookmark(self, collection: str, point_id: str, user: str = "default") -> bool:
        """Toggle bookmark status. Returns new bookmark state (True = bookmarked)."""
        with self._lock:
            row = self._conn.execute(
                "SELECT bookmark_id FROM bookmarks WHERE collection = ? AND point_id = ? AND user = ?",
                (collection, point_id, user),
            ).fetchone()
            if row:
                self._conn.execute(
                    "DELETE FROM bookmarks WHERE collection = ? AND point_id = ? AND user = ?",
                    (collection, point_id, user),
                )
                self._conn.commit()
                return False
            else:
                bm_id = str(uuid.uuid4())
                self._conn.execute(
                    "INSERT INTO bookmarks (bookmark_id, collection, point_id, user) VALUES (?, ?, ?, ?)",
                    (bm_id, collection, point_id, user),
                )
                self._conn.commit()
                return True

    def is_bookmarked(self, collection: str, point_id: str, user: str = "default") -> bool:
        row = self._conn.execute(
            "SELECT 1 FROM bookmarks WHERE collection = ? AND point_id = ? AND user = ?",
            (collection, point_id, user),
        ).fetchone()
        return row is not None

    def get_bookmarked(self, collection: str | None = None, user: str = "default") -> list[dict]:
        if collection:
            rows = self._conn.execute(
                "SELECT * FROM bookmarks WHERE collection = ? AND user = ? ORDER BY created_at DESC",
                (collection, user),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM bookmarks WHERE user = ? ORDER BY created_at DESC",
                (user,),
            ).fetchall()
        return [dict(r) for r in rows]

    def set_confidence(self, collection: str, point_id: str, confidence: float, author: str = "analyst") -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO confidence (collection, point_id, confidence_score, author, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (collection, point_id, confidence, author, datetime.now().isoformat()),
            )
            self._conn.commit()

    def get_confidence(self, collection: str, point_id: str) -> float | None:
        row = self._conn.execute(
            "SELECT confidence_score FROM confidence WHERE collection = ? AND point_id = ?",
            (collection, point_id),
        ).fetchone()
        return row["confidence_score"] if row else None

    def set_status(self, collection: str, point_id: str, status: str, author: str = "analyst") -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO status (collection, point_id, status, author, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (collection, point_id, status, author, datetime.now().isoformat()),
            )
            self._conn.commit()

    def get_status(self, collection: str, point_id: str) -> str | None:
        row = self._conn.execute(
            "SELECT status FROM status WHERE collection = ? AND point_id = ?",
            (collection, point_id),
        ).fetchone()
        return row["status"] if row else None

    def close(self) -> None:
        """Close the database connection."""
        if self._conn:
            self._conn.close()
