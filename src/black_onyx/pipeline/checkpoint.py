"""Checkpoint manager — SQLite-based resume/checkpoint for ingestion."""

from __future__ import annotations

import hashlib
import logging
import os
import sqlite3
import threading
from pathlib import Path

logger = logging.getLogger(__name__)


class CheckpointManager:
    """SQLite-backed checkpoint manager for ingestion resume.

    Tracks which (filepath, chunk_index) pairs have been processed,
    allowing ingestion to resume without reprocessing completed files.
    """

    def __init__(self, checkpoint_dir: str = ".checkpoints") -> None:
        """Initialize the checkpoint manager.

        Args:
            checkpoint_dir: Directory for the SQLite database file.
        """
        self._checkpoint_dir = Path(checkpoint_dir)
        self._checkpoint_dir.mkdir(parents=True, exist_ok=True)
        self._db_path = self._checkpoint_dir / "ingestion_checkpoint.sqlite"
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
        self._init_db()

    def _init_db(self) -> None:
        """Initialize the SQLite database schema."""
        with self._lock:
            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS processed_items (
                    file_hash TEXT NOT NULL,
                    chunk_index INTEGER NOT NULL,
                    filepath TEXT NOT NULL,
                    collection TEXT NOT NULL,
                    processed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY (file_hash, chunk_index, collection)
                )
            """)
            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS ingestion_runs (
                    run_id TEXT PRIMARY KEY,
                    directory TEXT NOT NULL,
                    collection TEXT NOT NULL,
                    total_files INTEGER,
                    processed_files INTEGER DEFAULT 0,
                    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    completed_at TIMESTAMP,
                    status TEXT DEFAULT 'running'
                )
            """)
            self._conn.commit()

    @staticmethod
    def _file_hash(filepath: str) -> str:
        """Fingerprint path and contents so changed files are reprocessed."""
        digest = hashlib.sha256()
        digest.update(os.path.abspath(filepath).encode("utf-8"))
        try:
            with open(filepath, "rb") as source:
                for block in iter(lambda: source.read(1024 * 1024), b""):
                    digest.update(block)
        except OSError:
            pass
        return digest.hexdigest()[:32]

    def is_processed(self, filepath: str, chunk_index: int, collection: str = "default") -> bool:
        """Check if a specific file chunk has already been processed.

        Args:
            filepath: Path to the file.
            chunk_index: Chunk index within the file.
            collection: Collection name (allows different checkpoints per collection).

        Returns:
            True if this chunk has been processed before.
        """
        fh = self._file_hash(filepath)
        with self._lock:
            cursor = self._conn.execute(
                "SELECT 1 FROM processed_items WHERE file_hash=? AND chunk_index=? AND collection=?",
                (fh, chunk_index, collection),
            )
            return cursor.fetchone() is not None

    def mark_processed(self, filepath: str, chunk_index: int, collection: str = "default") -> None:
        """Mark a file chunk as processed.

        Args:
            filepath: Path to the file.
            chunk_index: Chunk index within the file.
            collection: Collection name.
        """
        fh = self._file_hash(filepath)
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO processed_items (file_hash, chunk_index, filepath, collection) VALUES (?, ?, ?, ?)",
                (fh, chunk_index, filepath, collection),
            )
            self._conn.commit()

    def get_progress(self, collection: str = "default") -> dict:
        """Get checkpoint progress for a collection.

        Args:
            collection: Collection name.

        Returns:
            Dict with processed_count.
        """
        with self._lock:
            cursor = self._conn.execute(
                "SELECT COUNT(DISTINCT filepath) FROM processed_items WHERE collection=?",
                (collection,),
            )
            count = cursor.fetchone()[0] or 0
        return {"processed_files": count}

    def reset(self, collection: str | None = None) -> None:
        """Clear checkpoint data.

        Args:
            collection: If specified, only clear data for this collection.
                        If None, clear all checkpoint data.
        """
        with self._lock:
            if collection:
                self._conn.execute(
                    "DELETE FROM processed_items WHERE collection=?",
                    (collection,),
                )
            else:
                self._conn.execute("DELETE FROM processed_items")
            self._conn.commit()
        logger.info(f"Checkpoint reset (collection={collection or 'all'})")

    def start_run(self, run_id: str, directory: str, collection: str, total_files: int = 0) -> None:
        """Record the start of an ingestion run.

        Args:
            run_id: Unique run identifier.
            directory: Directory being ingested.
            collection: Target collection.
            total_files: Total number of files to process.
        """
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO ingestion_runs (run_id, directory, collection, total_files, status) VALUES (?, ?, ?, ?, 'running')",
                (run_id, directory, collection, total_files),
            )
            self._conn.commit()

    def complete_run(self, run_id: str, processed_files: int) -> None:
        """Mark an ingestion run as completed.

        Args:
            run_id: Unique run identifier.
            processed_files: Number of files actually processed.
        """
        with self._lock:
            self._conn.execute(
                "UPDATE ingestion_runs SET completed_at=CURRENT_TIMESTAMP, processed_files=?, status='completed' WHERE run_id=?",
                (processed_files, run_id),
            )
            self._conn.commit()

    def close(self) -> None:
        """Close the database connection."""
        with self._lock:
            self._conn.close()
