"""Chat session manager — in-memory and optional persistent chat history."""

from __future__ import annotations

import logging
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from black_onyx.llm.base import ChatMessage

logger = logging.getLogger(__name__)


class ChatSessionManager:
    """Manages chat sessions with optional SQLite persistence.

    Sessions store message history and metadata. If a persistence directory
    is provided, sessions are saved to SQLite; otherwise they are in-memory only.
    """

    def __init__(self, persist_dir: str | None = None) -> None:
        """Initialize the session manager.

        Args:
            persist_dir: Directory for SQLite persistence. If None, in-memory only.
        """
        self._persist_dir = Path(persist_dir) if persist_dir else None
        self._in_memory: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()
        self._conn: sqlite3.Connection | None = None

        if self._persist_dir:
            self._persist_dir.mkdir(parents=True, exist_ok=True)
            db_path = self._persist_dir / "chat_sessions.sqlite"
            self._conn = sqlite3.connect(str(db_path), check_same_thread=False)
            self._init_db()

    def _init_db(self) -> None:
        """Initialize the SQLite schema."""
        if not self._conn:
            return
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                owner_id TEXT NOT NULL DEFAULT '',
                title TEXT,
                provider TEXT,
                model TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        columns = {row[1] for row in self._conn.execute("PRAGMA table_info(sessions)")}
        if "owner_id" not in columns:
            self._conn.execute("ALTER TABLE sessions ADD COLUMN owner_id TEXT NOT NULL DEFAULT ''")
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                role TEXT NOT NULL,
                content TEXT NOT NULL,
                images TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (session_id) REFERENCES sessions(session_id)
            )
        """)
        self._conn.commit()

    def create_session(
        self,
        title: str = "New Chat",
        provider: str = "",
        model: str = "",
        owner_id: str = "",
    ) -> str:
        """Create a new chat session.

        Args:
            title: Session title.
            provider: LLM provider name.
            model: Model name.

        Returns:
            Session ID string.
        """
        session_id = str(uuid.uuid4())
        with self._lock:
            if self._conn:
                self._conn.execute(
                    "INSERT INTO sessions (session_id, owner_id, title, provider, model) VALUES (?, ?, ?, ?, ?)",
                    (session_id, owner_id, title, provider, model),
                )
                self._conn.commit()
            self._in_memory[session_id] = {
                "title": title,
                "provider": provider,
                "model": model,
                "messages": [],
                "owner_id": owner_id,
                "created_at": time.time(),
            }
        logger.debug(f"Created chat session: {session_id}")
        return session_id

    def add_message(
        self,
        session_id: str,
        role: str,
        content: str,
        images: list[str] | None = None,
    ) -> None:
        """Add a message to a session.

        Args:
            session_id: Session ID.
            role: Message role ("user", "assistant", "system").
            content: Message content.
            images: Optional list of image paths/base64 strings.
        """
        import json

        images_json = json.dumps(images) if images else None

        with self._lock:
            if self._conn:
                self._conn.execute(
                    "INSERT INTO messages (session_id, role, content, images) VALUES (?, ?, ?, ?)",
                    (session_id, role, content, images_json),
                )
                self._conn.execute(
                    "UPDATE sessions SET updated_at=CURRENT_TIMESTAMP WHERE session_id=?",
                    (session_id,),
                )
                self._conn.commit()

            if session_id in self._in_memory:
                self._in_memory[session_id]["messages"].append(
                    ChatMessage(role=role, content=content, images=images)
                )

    def get_messages(self, session_id: str) -> list[ChatMessage]:
        """Get all messages for a session.

        Args:
            session_id: Session ID.

        Returns:
            List of ChatMessage objects.
        """
        import json

        with self._lock:
            if self._conn:
                cursor = self._conn.execute(
                    "SELECT role, content, images FROM messages WHERE session_id=? ORDER BY id",
                    (session_id,),
                )
                messages: list[ChatMessage] = []
                for row in cursor:
                    role, content, images_json = row
                    images = json.loads(images_json) if images_json else None
                    messages.append(ChatMessage(role=role, content=content, images=images))
                return messages

            if session_id in self._in_memory:
                return list(self._in_memory[session_id]["messages"])

        return []

    def list_sessions(self, owner_id: str | None = None) -> list[dict[str, Any]]:
        """List all chat sessions.

        Returns:
            List of session metadata dicts.
        """
        with self._lock:
            if self._conn:
                if owner_id is None:
                    cursor = self._conn.execute(
                        "SELECT session_id,title,provider,model,created_at,updated_at FROM sessions ORDER BY updated_at DESC"
                    )
                else:
                    cursor = self._conn.execute(
                        "SELECT session_id,title,provider,model,created_at,updated_at FROM sessions "
                        "WHERE owner_id=? ORDER BY updated_at DESC", (owner_id,)
                    )
                return [
                    {
                        "session_id": row[0],
                        "title": row[1],
                        "provider": row[2],
                        "model": row[3],
                        "created_at": row[4],
                        "updated_at": row[5],
                    }
                    for row in cursor
                ]

            return [
                {
                    "session_id": sid,
                    "title": s["title"],
                    "provider": s["provider"],
                    "model": s["model"],
                    "created_at": s["created_at"],
                }
                for sid, s in self._in_memory.items()
                if owner_id is None or s.get("owner_id") == owner_id
            ]

    def is_owner(self, session_id: str, owner_id: str) -> bool:
        if self._conn:
            row = self._conn.execute(
                "SELECT 1 FROM sessions WHERE session_id=? AND owner_id=?", (session_id, owner_id)
            ).fetchone()
            return row is not None
        return self._in_memory.get(session_id, {}).get("owner_id") == owner_id

    def get_session(self, session_id: str) -> dict[str, Any] | None:
        with self._lock:
            if self._conn:
                row = self._conn.execute(
                    "SELECT session_id,owner_id,title,provider,model FROM sessions WHERE session_id=?",
                    (session_id,),
                ).fetchone()
                if row:
                    return {
                        "session_id": row[0], "owner_id": row[1], "title": row[2],
                        "provider": row[3], "model": row[4],
                    }
                return None
            session = self._in_memory.get(session_id)
            return {"session_id": session_id, **session} if session else None

    def delete_session(self, session_id: str) -> None:
        """Delete a chat session and all its messages.

        Args:
            session_id: Session ID to delete.
        """
        with self._lock:
            if self._conn:
                self._conn.execute("DELETE FROM messages WHERE session_id=?", (session_id,))
                self._conn.execute("DELETE FROM sessions WHERE session_id=?", (session_id,))
                self._conn.commit()
            self._in_memory.pop(session_id, None)

    def update_session_title(self, session_id: str, title: str) -> None:
        """Update a session's title.

        Args:
            session_id: Session ID.
            title: New title.
        """
        with self._lock:
            if self._conn:
                self._conn.execute(
                    "UPDATE sessions SET title=?, updated_at=CURRENT_TIMESTAMP WHERE session_id=?",
                    (title, session_id),
                )
                self._conn.commit()
            if session_id in self._in_memory:
                self._in_memory[session_id]["title"] = title

    def close(self) -> None:
        """Close the database connection."""
        with self._lock:
            if self._conn:
                self._conn.close()
                self._conn = None
