"""Progress tracking for ingestion jobs — thread-safe with callback hooks for WebSocket/SSE."""

from __future__ import annotations

import logging
import threading
import time
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)


class ProgressTracker:
    """Thread-safe progress tracker for ingestion jobs.

    Tracks processed files, errors, speed, and current file being processed.
    Supports callback hooks for real-time updates via WebSocket or SSE.
    """

    def __init__(
        self,
        total_files: int = 0,
        callback: Optional[Callable[[dict[str, Any]], None]] = None,
    ) -> None:
        """Initialize the progress tracker.

        Args:
            total_files: Total number of files to process.
            callback: Optional callback function called on each progress update.
                      Receives a dict with progress information.
        """
        self._total = total_files
        self._processed = 0
        self._errors = 0
        self._total_chunks = 0
        self._current_file: Optional[str] = None
        self._start_time = time.time()
        self._lock = threading.Lock()
        self._callback = callback
        self._recent_activity: list[dict[str, Any]] = []
        self._error_details: list[dict[str, Any]] = []
        self._stopped = False

    def set_callback(self, callback: Callable[[dict[str, Any]], None]) -> None:
        """Set or replace the progress callback."""
        self._callback = callback

    def set_total(self, total: int) -> None:
        """Set the total file count (used after directory walk)."""
        with self._lock:
            self._total = total

    def on_file_start(self, filepath: str) -> None:
        """Called when processing of a file begins."""
        with self._lock:
            self._current_file = filepath
        self._notify("file_start", {"filepath": filepath})

    def on_file_done(self, filepath: str, chunks: int, duration_ms: float) -> None:
        """Called when a file is successfully processed."""
        with self._lock:
            self._processed += 1
            self._total_chunks += chunks
            self._current_file = None
            self._recent_activity.append({
                "filepath": filepath,
                "chunks": chunks,
                "duration_ms": duration_ms,
                "status": "done",
                "timestamp": time.time(),
            })
            # Keep only last 50 activities
            if len(self._recent_activity) > 50:
                self._recent_activity = self._recent_activity[-50:]
        self._notify("file_done", {
            "filepath": filepath,
            "chunks": chunks,
            "duration_ms": duration_ms,
        })
        self._notify_progress()

    def on_file_error(self, filepath: str, error: str) -> None:
        """Called when a file fails to process."""
        with self._lock:
            self._errors += 1
            self._processed += 1
            self._current_file = None
            self._error_details.append({
                "filepath": filepath,
                "error": error,
                "timestamp": time.time(),
            })
            self._recent_activity.append({
                "filepath": filepath,
                "error": error,
                "status": "error",
                "timestamp": time.time(),
            })
            if len(self._recent_activity) > 50:
                self._recent_activity = self._recent_activity[-50:]
            if len(self._error_details) > 500:
                self._error_details = self._error_details[-500:]
        self._notify("file_error", {"filepath": filepath, "error": error})
        self._notify_progress()

    def on_ingest_complete(self) -> None:
        """Called when the entire ingestion job is complete."""
        elapsed = time.time() - self._start_time
        with self._lock:
            stats = {
                "total_chunks": self._total_chunks,
                "total_errors": self._errors,
                "duration_s": round(elapsed, 2),
            }
        self._notify("ingest_complete", stats)

    def stop(self) -> None:
        """Signal the ingestion to stop gracefully."""
        with self._lock:
            self._stopped = True

    @property
    def stopped(self) -> bool:
        with self._lock:
            return self._stopped

    def get_status(self) -> dict[str, Any]:
        """Get the current ingestion status.

        Returns:
            Dict with: processed, total, errors, total_chunks, speed_fps,
            current_file, elapsed_s, recent_activity, error_details.
        """
        with self._lock:
            elapsed = time.time() - self._start_time
            speed = self._processed / elapsed if elapsed > 0 else 0.0
            return {
                "processed": self._processed,
                "total": self._total,
                "errors": self._errors,
                "total_chunks": self._total_chunks,
                "speed_fps": round(speed, 2),
                "current_file": self._current_file,
                "elapsed_s": round(elapsed, 2),
                "recent_activity": list(self._recent_activity),
                "error_details": list(self._error_details),
                "running": self._current_file is not None and not self._stopped,
            }

    def _notify_progress(self) -> None:
        """Send a progress update event."""
        with self._lock:
            elapsed = time.time() - self._start_time
            speed = self._processed / elapsed if elapsed > 0 else 0.0
            data = {
                "processed": self._processed,
                "total": self._total,
                "errors": self._errors,
                "speed_fps": round(speed, 2),
            }
        self._notify("progress", data)

    def _notify(self, event: str, data: dict[str, Any]) -> None:
        """Send an event to the callback if one is set."""
        if self._callback:
            try:
                self._callback({"event": event, **data})
            except Exception as e:
                logger.debug(f"Progress callback error: {e}")
