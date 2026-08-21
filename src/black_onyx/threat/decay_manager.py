"""IOC decay and freshness tracking — score IOCs based on age and sightings."""

from __future__ import annotations

import logging
import math
import sqlite3
import threading
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)


class DecayManager:
    """Tracks IOC freshness and calculates decay scores.

    IOCs decay over time based on:
    - First seen date
    - Last seen date
    - Number of sightings
    - Source diversity

    Decay score: 1.0 (fresh) -> 0.0 (stale/expired)
    Score = exp(-decay_rate * days_since_last_seen) * min(1.0, sighting_count / 10)
    """

    def __init__(
        self,
        persist_dir: str | None = None,
        decay_rate: float = 0.01,
        stale_threshold_days: int = 90,
    ) -> None:
        self._decay_rate = decay_rate
        self._stale_threshold_days = stale_threshold_days
        self._persist_dir = Path(persist_dir) if persist_dir else None
        self._lock = threading.Lock()
        db_path = ":memory:"
        if self._persist_dir:
            self._persist_dir.mkdir(parents=True, exist_ok=True)
            db_path = str(self._persist_dir / "ioc_decay.sqlite")
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_db()

    def _init_db(self) -> None:
        if not self._conn:
            return
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS ioc_tracking (
                ioc_type TEXT NOT NULL,
                ioc_value TEXT NOT NULL,
                first_seen TIMESTAMP,
                last_seen TIMESTAMP,
                sighting_count INTEGER DEFAULT 1,
                source_count INTEGER DEFAULT 1,
                decay_score REAL DEFAULT 1.0,
                last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (ioc_type, ioc_value)
            );
            CREATE TABLE IF NOT EXISTS ioc_sources (
                ioc_value TEXT NOT NULL,
                source TEXT NOT NULL,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (ioc_value, source)
            );
        """)
        self._conn.commit()

    def record_sighting(self, ioc_type: str, ioc_value: str, source: str = "") -> None:
        """Record a sighting of an IOC."""
        now = datetime.now().isoformat()
        with self._lock:
            existing = self._conn.execute(
                "SELECT * FROM ioc_tracking WHERE ioc_type = ? AND ioc_value = ?",
                (ioc_type, ioc_value),
            ).fetchone()
            if existing:
                self._conn.execute(
                    "UPDATE ioc_tracking SET last_seen = ?, sighting_count = sighting_count + 1, "
                    "last_updated = ? WHERE ioc_type = ? AND ioc_value = ?",
                    (now, now, ioc_type, ioc_value),
                )
            else:
                self._conn.execute(
                    "INSERT INTO ioc_tracking (ioc_type, ioc_value, first_seen, last_seen, sighting_count, decay_score, last_updated) "
                    "VALUES (?, ?, ?, ?, 1, 1.0, ?)",
                    (ioc_type, ioc_value, now, now, now),
                )
            if source:
                self._conn.execute(
                    "INSERT OR IGNORE INTO ioc_sources (ioc_value, source) VALUES (?, ?)",
                    (ioc_value, source),
                )
                # Update source count
                src_count = self._conn.execute(
                    "SELECT COUNT(*) as cnt FROM ioc_sources WHERE ioc_value = ?",
                    (ioc_value,),
                ).fetchone()["cnt"]
                self._conn.execute(
                    "UPDATE ioc_tracking SET source_count = ? WHERE ioc_value = ?",
                    (src_count, ioc_value),
                )
            self._conn.commit()

    def record_sightings_batch(self, iocs: dict[str, list], source: str = "") -> None:
        """Record sightings for a batch of IOCs from ingestion."""
        type_map = {
            "ipv4": "ip", "ipv6": "ip", "domain": "domain", "url": "url",
            "md5": "hash", "sha1": "hash", "sha256": "hash", "sha512": "hash",
            "email": "email", "cve": "cve",
        }
        for ioc_type_key, values in iocs.items():
            if not isinstance(values, list):
                continue
            ioc_type = type_map.get(ioc_type_key, ioc_type_key)
            for value in values:
                self.record_sighting(ioc_type, value, source)

    def calculate_decay_score(self, ioc_value: str) -> float:
        """Calculate the current decay score for an IOC."""
        row = self._conn.execute(
            "SELECT last_seen, sighting_count FROM ioc_tracking WHERE ioc_value = ?",
            (ioc_value,),
        ).fetchone()
        if not row:
            return 1.0
        last_seen = datetime.fromisoformat(row["last_seen"])
        days_since = (datetime.now() - last_seen).days
        sighting_factor = min(1.0, row["sighting_count"] / 10.0)
        score = math.exp(-self._decay_rate * days_since) * sighting_factor
        return max(0.0, min(1.0, score))

    def update_all_scores(self) -> int:
        """Recalculate decay scores for all tracked IOCs. Returns count updated."""
        rows = self._conn.execute(
            "SELECT ioc_value FROM ioc_tracking",
        ).fetchall()
        count = 0
        for row in rows:
            score = self.calculate_decay_score(row["ioc_value"])
            with self._lock:
                self._conn.execute(
                    "UPDATE ioc_tracking SET decay_score = ?, last_updated = ? WHERE ioc_value = ?",
                    (score, datetime.now().isoformat(), row["ioc_value"]),
                )
            count += 1
        with self._lock:
            self._conn.commit()
        return count

    def get_stale_iocs(self, threshold_score: float = 0.3) -> list[dict]:
        """Get IOCs with decay score below threshold."""
        rows = self._conn.execute(
            "SELECT * FROM ioc_tracking WHERE decay_score < ? ORDER BY decay_score ASC",
            (threshold_score,),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_fresh_iocs(self, threshold_score: float = 0.7) -> list[dict]:
        """Get IOCs with decay score above threshold."""
        rows = self._conn.execute(
            "SELECT * FROM ioc_tracking WHERE decay_score >= ? ORDER BY decay_score DESC",
            (threshold_score,),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_ioc_history(self, ioc_value: str) -> dict | None:
        """Get tracking history for a specific IOC."""
        row = self._conn.execute(
            "SELECT * FROM ioc_tracking WHERE ioc_value = ?",
            (ioc_value,),
        ).fetchone()
        if not row:
            return None
        result = dict(row)
        result["current_decay_score"] = self.calculate_decay_score(ioc_value)
        sources = self._conn.execute(
            "SELECT source FROM ioc_sources WHERE ioc_value = ?",
            (ioc_value,),
        ).fetchall()
        result["sources"] = [r["source"] for r in sources]
        return result

    def get_all_tracked(self, limit: int = 100) -> list[dict]:
        """Get all tracked IOCs with their decay scores."""
        rows = self._conn.execute(
            "SELECT * FROM ioc_tracking ORDER BY last_seen DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_summary(self, stale_threshold: float = 0.3, fresh_threshold: float = 0.7) -> dict:
        """Cheap COUNT(*)-backed aggregate for dashboard/gallery tiles.

        Unlike get_stale_iocs/get_fresh_iocs, this never materializes full IOC
        rows, so it is safe to call even when the tracked set is large.
        """
        tracked_count = self._conn.execute(
            "SELECT COUNT(*) AS n FROM ioc_tracking",
        ).fetchone()["n"]
        stale_count = self._conn.execute(
            "SELECT COUNT(*) AS n FROM ioc_tracking WHERE decay_score < ?",
            (stale_threshold,),
        ).fetchone()["n"]
        fresh_count = self._conn.execute(
            "SELECT COUNT(*) AS n FROM ioc_tracking WHERE decay_score >= ?",
            (fresh_threshold,),
        ).fetchone()["n"]
        last_updated = self._conn.execute(
            "SELECT MAX(last_updated) AS ts FROM ioc_tracking",
        ).fetchone()["ts"]
        return {
            "tracked_count": tracked_count,
            "stale_count": stale_count,
            "fresh_count": fresh_count,
            "last_updated": last_updated,
        }

    def close(self) -> None:
        """Close the database connection."""
        if self._conn:
            self._conn.close()
