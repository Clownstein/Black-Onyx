"""Enrichment manager — orchestrates multi-provider IOC enrichment with SQLite caching."""

from __future__ import annotations

import asyncio
import json
import logging
import re
import sqlite3
import threading
import time
import weakref
from pathlib import Path
from typing import Any

from black_onyx.enrichment.base import EnrichmentProvider, EnrichmentResult

logger = logging.getLogger(__name__)


class EnrichmentManager:
    """Orchestrates multi-provider IOC enrichment.

    Manages provider instances, handles rate limiting, caches results in SQLite,
    and aggregates enrichment data across providers.
    """

    def __init__(
        self,
        providers: list[EnrichmentProvider],
        persist_dir: str | None = None,
        cache_ttl_hours: int = 24,
        max_concurrent: int = 5,
        timeout_seconds: int = 30,
    ) -> None:
        self._providers = {p.name: p for p in providers}
        self._cache_ttl = cache_ttl_hours * 3600
        self._max_concurrent = max_concurrent
        # One semaphore per running loop, created lazily — see
        # _get_semaphore(). This manager is a long-lived singleton driven from
        # more than one event loop. Weak keys so the entry for a short-lived
        # loop disappears when that loop is collected, rather than
        # accumulating one per ingestion for the life of the process.
        self._semaphores: "weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, asyncio.Semaphore]" = (
            weakref.WeakKeyDictionary()
        )
        self._timeout_seconds = timeout_seconds
        self._lock = threading.Lock()
        self._conn: sqlite3.Connection | None = None

        if persist_dir:
            persist_path = Path(persist_dir)
            persist_path.mkdir(parents=True, exist_ok=True)
            db_path = persist_path / "enrichment_cache.sqlite"
            self._conn = sqlite3.connect(str(db_path), check_same_thread=False)
            self._init_db()

    def _init_db(self) -> None:
        if not self._conn:
            return
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS enrichment_cache (
                cache_key TEXT PRIMARY KEY,
                provider TEXT NOT NULL,
                ioc_type TEXT NOT NULL,
                ioc_value TEXT NOT NULL,
                result_json TEXT NOT NULL,
                cached_at REAL NOT NULL
            )
        """)
        self._conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_cache_ioc
            ON enrichment_cache(ioc_type, ioc_value)
        """)
        self._conn.commit()

    def _cache_key(self, provider: str, ioc_type: str, ioc_value: str) -> str:
        return f"{provider}:{ioc_type}:{ioc_value}"

    def _get_cached(self, provider: str, ioc_type: str, ioc_value: str) -> EnrichmentResult | None:
        if not self._conn:
            return None
        key = self._cache_key(provider, ioc_type, ioc_value)
        with self._lock:
            row = self._conn.execute(
                "SELECT result_json, cached_at FROM enrichment_cache WHERE cache_key = ?",
                (key,),
            ).fetchone()
        if row:
            result_json, cached_at = row
            if time.time() - cached_at < self._cache_ttl:
                data = json.loads(result_json)
                return EnrichmentResult(**data)
        return None

    def _set_cached(self, result: EnrichmentResult) -> None:
        if not self._conn:
            return
        key = self._cache_key(result.provider, result.ioc_type, result.ioc_value)
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO enrichment_cache (cache_key, provider, ioc_type, ioc_value, result_json, cached_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (key, result.provider, result.ioc_type, result.ioc_value,
                 json.dumps(result.to_dict()), time.time()),
            )
            self._conn.commit()

    @staticmethod
    def classify_ioc_type(value: str) -> str:
        """Auto-detect IOC type from value."""
        if re.match(r"^CVE-\d{4}-\d{4,}$", value, re.IGNORECASE):
            return "cve"
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", value):
            return "ip"
        if re.match(r"^[a-fA-F0-9]{32}$", value):
            return "hash"
        if re.match(r"^[a-fA-F0-9]{40}$", value):
            return "hash"
        if re.match(r"^[a-fA-F0-9]{64}$", value):
            return "hash"
        if value.startswith("http://") or value.startswith("https://"):
            return "url"
        if "@" in value and "." in value:
            return "email"
        if re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", value):
            return "domain"
        return "unknown"

    async def enrich_ioc(
        self,
        ioc_type: str,
        ioc_value: str,
        providers: list[str] | None = None,
    ) -> list[EnrichmentResult]:
        """Enrich a single IOC across all (or specified) providers."""
        provider_names = providers or list(self._providers.keys())
        tasks = []
        for name in provider_names:
            provider = self._providers.get(name)
            if not provider:
                continue
            if ioc_type not in provider.supported_ioc_types:
                continue
            tasks.append(self._enrich_with_provider(provider, ioc_type, ioc_value))
        if not tasks:
            return []
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for r in results if isinstance(r, EnrichmentResult)]

    def _get_semaphore(self) -> asyncio.Semaphore:
        """Return a concurrency semaphore owned by the *currently running* loop.

        `asyncio.Semaphore` binds itself to a loop the first time it actually
        has to suspend a waiter, and then raises
        "is bound to a different event loop" if used from anywhere else. This
        manager is a process-wide singleton reached from two different loops:
        the FastAPI loop (interactive /enrich requests) and the short-lived
        loops `asyncio.run()` creates for playbook triggers fired from
        ingestion worker threads. A single semaphore built in __init__ would
        therefore work until the first time more than `max_concurrent`
        enrichments contended, and from then on permanently fail for whichever
        loop did not claim it — including breaking the interactive endpoint
        because a background ingestion happened to claim it first.

        Rebinding per loop keeps the concurrency cap meaningful (it bounds
        in-flight provider calls within the loop actually issuing them) while
        removing the cross-loop failure entirely.
        """
        loop = asyncio.get_running_loop()
        with self._lock:
            semaphore = self._semaphores.get(loop)
            if semaphore is None:
                semaphore = asyncio.Semaphore(self._max_concurrent)
                self._semaphores[loop] = semaphore
            return semaphore

    async def _enrich_with_provider(
        self, provider: EnrichmentProvider, ioc_type: str, ioc_value: str,
    ) -> EnrichmentResult:
        async with self._get_semaphore():
            cached = self._get_cached(provider.name, ioc_type, ioc_value)
            if cached:
                return cached
            try:
                result = await asyncio.wait_for(
                    provider.enrich(ioc_type, ioc_value),
                    timeout=self._timeout_seconds,
                )
                self._set_cached(result)
                return result
            except asyncio.TimeoutError:
                logger.warning("Enrichment provider %s timed out", provider.name)
                return EnrichmentResult(
                    provider=provider.name, ioc_type=ioc_type, ioc_value=ioc_value,
                    error="Provider request timed out",
                )
            except Exception:
                logger.exception("Enrichment provider %s failed", provider.name)
                return EnrichmentResult(
                    provider=provider.name, ioc_type=ioc_type, ioc_value=ioc_value,
                    error="Provider request failed",
                )

    async def enrich_batch(
        self, iocs: list[tuple[str, str]],
    ) -> dict[str, list[EnrichmentResult]]:
        """Enrich a batch of IOCs concurrently.

        Args:
            iocs: List of (ioc_type, ioc_value) tuples.

        Returns:
            Dict mapping ioc_value to list of EnrichmentResults.
        """
        tasks = []
        for ioc_type, ioc_value in iocs:
            tasks.append(self.enrich_ioc(ioc_type, ioc_value))
        all_results = await asyncio.gather(*tasks, return_exceptions=True)
        result_map: dict[str, list[EnrichmentResult]] = {}
        for (ioc_type, ioc_value), results in zip(iocs, all_results):
            if isinstance(results, list):
                result_map[ioc_value] = results
            else:
                result_map[ioc_value] = []
        return result_map

    def list_providers(self) -> list[dict[str, Any]]:
        """List all configured providers with their supported IOC types."""
        return [
            {"name": p.name, "supported_ioc_types": p.supported_ioc_types}
            for p in self._providers.values()
        ]

    def list_cached_results(self, limit: int = 500) -> list[dict[str, Any]]:
        """Return recent enrichment cache rows for analytics (geo / CVE boards)."""
        if not self._conn:
            return []
        with self._lock:
            rows = self._conn.execute(
                "SELECT provider, ioc_type, ioc_value, result_json, cached_at "
                "FROM enrichment_cache ORDER BY cached_at DESC LIMIT ?",
                (max(1, min(limit, 5_000)),),
            ).fetchall()
        out: list[dict[str, Any]] = []
        for row in rows:
            provider, ioc_type, ioc_value, result_json = row[0], row[1], row[2], row[3]
            try:
                data = json.loads(result_json)
            except Exception:
                data = {}
            if not isinstance(data, dict):
                data = {}
            out.append({
                "provider": provider or data.get("provider"),
                "ioc_type": ioc_type or data.get("ioc_type"),
                "ioc_value": ioc_value or data.get("ioc_value"),
                "tags": data.get("tags") or [],
                "raw_data": data.get("raw_data") or {},
                "confidence": data.get("confidence"),
            })
        return out
