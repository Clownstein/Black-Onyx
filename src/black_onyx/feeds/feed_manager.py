"""Feed ingestion — RSS/Atom and TAXII 2.1 feed support."""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import logging
import sqlite3
import threading
import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from black_onyx_contracts.html_escape import contains_raw_script_tag, escape_for_ui

logger = logging.getLogger(__name__)

# Many publishers reject requests without a descriptive agent or feed Accept type.
DEFAULT_FETCH_HEADERS = {
    "User-Agent": "BlackOnyx/1.0 (threat-intelligence feed reader)",
    "Accept": (
        "application/rss+xml, application/atom+xml, application/xml;q=0.9, "
        "text/xml;q=0.8, application/json;q=0.7, */*;q=0.5"
    ),
    "Accept-Language": "en-US,en;q=0.9",
}


class FeedFetchError(Exception):
    """A feed could not be retrieved, carrying an operator-readable reason."""


class FeedManager:
    """Manages RSS/Atom and TAXII feed ingestion.

    Polls feeds on a schedule, extracts IOCs from feed content,
    and ingests into Qdrant collections.
    """

    def __init__(
        self,
        persist_dir: str | None = None,
        ingestor: Any = None,
        allowed_hosts: list[str] | None = None,
        max_response_bytes: int = 10 * 1024 * 1024,
        max_concurrent: int = 4,
        max_items_per_poll: int = 40,
    ) -> None:
        self._ingestor = ingestor
        self._lock = threading.Lock()
        self._persist_dir = Path(persist_dir) if persist_dir else None
        self._allowed_hosts = {h.casefold() for h in (allowed_hosts or [])}
        self._max_response_bytes = max_response_bytes
        self._max_concurrent = max_concurrent
        # Archive feeds publish thousands of entries; ingest them across polls so a
        # single fetch cannot monopolise the embedding pipeline.
        self._max_items_per_poll = max(1, max_items_per_poll)
        self._scheduler_stop = threading.Event()
        self._scheduler_thread: threading.Thread | None = None
        db_path = ":memory:"
        if self._persist_dir:
            self._persist_dir.mkdir(parents=True, exist_ok=True)
            db_path = str(self._persist_dir / "feeds.sqlite")
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_db()

    def _init_db(self) -> None:
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS feeds (
                name TEXT PRIMARY KEY,
                url TEXT NOT NULL,
                feed_type TEXT NOT NULL,
                collection TEXT,
                enabled INTEGER DEFAULT 1,
                poll_interval_minutes INTEGER DEFAULT 60,
                last_poll TIMESTAMP,
                config TEXT
            );
            CREATE TABLE IF NOT EXISTS seen_items (
                feed_name TEXT NOT NULL,
                item_url TEXT NOT NULL,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (feed_name, item_url)
            );
        """)
        existing = {row["name"] for row in self._conn.execute("PRAGMA table_info(feeds)")}
        for column, ddl in (
            ("last_attempt", "ALTER TABLE feeds ADD COLUMN last_attempt TIMESTAMP"),
            ("last_status", "ALTER TABLE feeds ADD COLUMN last_status TEXT"),
            ("last_error", "ALTER TABLE feeds ADD COLUMN last_error TEXT"),
            ("last_items", "ALTER TABLE feeds ADD COLUMN last_items INTEGER DEFAULT 0"),
        ):
            if column not in existing:
                self._conn.execute(ddl)
        self._conn.commit()

    def _record_outcome(self, name: str, result: dict[str, Any]) -> None:
        """Persist the outcome of a poll so feed health survives a page reload."""
        error = result.get("error")
        with self._lock:
            self._conn.execute(
                "UPDATE feeds SET last_attempt = ?, last_status = ?, last_error = ?, "
                "last_items = ? WHERE name = ?",
                (
                    datetime.now().isoformat(),
                    "failed" if error else "ok",
                    error,
                    int(result.get("items_processed") or 0),
                    name,
                ),
            )
            self._conn.commit()

    def add_feed(
        self, name: str, url: str, feed_type: str = "rss",
        collection: str = "all-knowledge", poll_interval_minutes: int = 60,
        config: dict | None = None,
    ) -> None:
        """Register a new feed."""
        if config and "password" in config:
            raise ValueError("TAXII passwords must be referenced by password_env")
        parsed = urlparse(url)
        if parsed.scheme != "https" or not parsed.hostname:
            raise ValueError("Feed URLs must use HTTPS")
        if self._allowed_hosts and parsed.hostname.casefold() not in self._allowed_hosts:
            raise ValueError("Feed hostname is not allowlisted")
        config_json = json.dumps(config) if config else None
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO feeds (name, url, feed_type, collection, enabled, poll_interval_minutes, config) "
                "VALUES (?, ?, ?, ?, 1, ?, ?)",
                (name, url, feed_type, collection, poll_interval_minutes, config_json),
            )
            self._conn.commit()

    def add_feed_from_dict(self, d: dict[str, Any]) -> None:
        """Add a feed from a config dict."""
        self.add_feed(
            name=d.get("name", ""),
            url=d.get("url", ""),
            feed_type=d.get("feed_type", "rss"),
            collection=d.get("collection", "all-knowledge"),
            poll_interval_minutes=d.get("poll_interval_minutes", 60),
            config=d.get("config"),
        )

    def remove_feed(self, name: str) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM feeds WHERE name = ?", (name,))
            self._conn.execute("DELETE FROM seen_items WHERE feed_name = ?", (name,))
            self._conn.commit()

    def list_feeds(self) -> list[dict]:
        rows = self._conn.execute("SELECT * FROM feeds ORDER BY name").fetchall()
        return [dict(r) for r in rows]

    async def poll_feed(self, feed_name: str) -> dict[str, Any]:
        """Poll a single feed and process new items."""
        row = self._conn.execute(
            "SELECT * FROM feeds WHERE name = ? AND enabled = 1", (feed_name,),
        ).fetchone()
        if not row:
            return {"error": "Feed not found or disabled"}

        feed = dict(row)
        if feed["feed_type"] in ("rss", "atom"):
            result = await self._poll_rss(feed)
        elif feed["feed_type"] == "taxii":
            result = await self._poll_taxii(feed)
        else:
            result = {
                "feed": feed_name,
                "error": f"Unknown feed type: {feed['feed_type']}",
            }
        self._record_outcome(feed_name, result)
        return result

    async def _poll_rss(self, feed: dict) -> dict[str, Any]:
        """Poll an RSS/Atom feed using feedparser."""
        try:
            import feedparser
        except ImportError:
            return {"error": "feedparser not installed"}

        try:
            body = await self._safe_fetch(feed["url"])
            parsed = feedparser.parse(body)
            if not parsed.entries and parsed.get("bozo") and parsed.get("bozo_exception"):
                return {
                    "feed": feed["name"],
                    "items_processed": 0,
                    "iocs_extracted": 0,
                    "error": f"Response is not a valid RSS/Atom feed: {parsed['bozo_exception']}",
                }
            items_processed = 0
            iocs_extracted = 0
            items_failed = 0
            last_failure = ""
            deferred = 0

            for entry in parsed.entries:
                if items_processed >= self._max_items_per_poll:
                    deferred += 1
                    continue
                title = entry.get("title", "")
                url = entry.get("link") or entry.get("id") or ""
                if not url:
                    url = "sha256:" + hashlib.sha256(title.encode("utf-8")).hexdigest()
                # Check if already seen
                existing = self._conn.execute(
                    "SELECT 1 FROM seen_items WHERE feed_name = ? AND item_url = ?",
                    (feed["name"], url),
                ).fetchone()
                if existing:
                    continue

                # Extract content
                content = ""
                if entry.get("content"):
                    content = entry["content"][0].get("value", "")
                elif entry.get("summary"):
                    content = entry["summary"]

                # Extract IOCs from content
                from black_onyx.extraction.ioc import extract_iocs
                iocs = extract_iocs(f"{title} {content}")
                iocs_extracted += iocs.total_count

                if self._ingestor and content.strip():
                    import tempfile
                    safe_name = hashlib.sha256(url.encode()).hexdigest()[:20] + ".html"
                    if contains_raw_script_tag(content):
                        logger.warning(
                            "feed %s item %s contains a raw <script>/javascript: fragment; "
                            "ingesting for evidence but flagging for review",
                            feed["name"], url,
                        )
                    try:
                        with tempfile.TemporaryDirectory(prefix="blackonyx_feed_") as tmp:
                            item_path = Path(tmp) / safe_name
                            # title is plain text per RSS/Atom spec and is escaped before
                            # embedding in markup; content is feed-supplied HTML and is
                            # left as-is for the ingestor's own extraction/sanitization.
                            item_path.write_text(
                                f"<h1>{escape_for_ui(title)}</h1>{content}", encoding="utf-8"
                            )
                            # process_file is CPU/GPU bound and synchronous; keep the
                            # event loop free so concurrent polls and requests continue.
                            await asyncio.to_thread(
                                self._ingestor.process_file, str(item_path), feed["collection"],
                            )
                    except Exception as exc:
                        items_failed += 1
                        last_failure = f"{type(exc).__name__}: {exc}"
                        logger.warning(
                            "Feed item ingest failed for %s (%s): %s", feed["name"], url, exc,
                        )
                        continue

                # Mark as seen
                with self._lock:
                    self._conn.execute(
                        "INSERT OR IGNORE INTO seen_items (feed_name, item_url) VALUES (?, ?)",
                        (feed["name"], url),
                    )
                    self._conn.commit()

                items_processed += 1

            # Update last poll time
            with self._lock:
                self._conn.execute(
                    "UPDATE feeds SET last_poll = ? WHERE name = ?",
                    (datetime.now().isoformat(), feed["name"]),
                )
                self._conn.commit()

            result: dict[str, Any] = {
                "feed": feed["name"],
                "items_available": len(parsed.entries),
                "items_processed": items_processed,
                "iocs_extracted": iocs_extracted,
            }
            if deferred:
                result["items_deferred"] = deferred
            if items_failed:
                result["items_failed"] = items_failed
                result["error"] = f"{items_failed} item(s) failed to ingest — {last_failure}"
            return result
        except (FeedFetchError, ValueError) as exc:
            logger.warning("RSS poll failed for %s: %s", feed["name"], exc)
            return {"feed": feed["name"], "error": str(exc)}
        except Exception as exc:
            logger.exception("RSS poll failed for %s", feed["name"])
            return {"feed": feed["name"], "error": f"Feed poll failed: {type(exc).__name__}"}

    async def _poll_taxii(self, feed: dict) -> dict[str, Any]:
        """Poll a TAXII collection through the same bounded SSRF-safe fetcher."""
        try:
            config = json.loads(feed.get("config") or "{}")
            collection_url = feed["url"]
            await self._validate_remote_url(collection_url)
            username = config.get("username")
            password_env = config.get("password_env")
            password = os.environ.get(password_env, "") if password_env else None
            if password_env and not password:
                raise ValueError("Configured TAXII password environment variable is unavailable")

            items_processed = 0
            iocs_extracted = 0
            objects_url = collection_url.rstrip("/") + "/objects/"
            from urllib.parse import urlencode
            import httpx
            auth = httpx.BasicAuth(username, password) if username and password else None
            objects: list[dict[str, Any]] = []
            next_token: str | None = None
            for _ in range(100):
                page_url = objects_url
                if next_token:
                    page_url += "?" + urlencode({"next": next_token})
                page = json.loads(await self._safe_fetch(
                    page_url, auth=auth,
                    headers={"Accept": "application/taxii+json;version=2.1, application/json"},
                ))
                page_objects = page.get("objects", [])
                if not isinstance(page_objects, list):
                    raise ValueError("TAXII response has an invalid objects collection")
                objects.extend(obj for obj in page_objects if isinstance(obj, dict))
                if not page.get("more"):
                    break
                next_token = page.get("next")
                if not isinstance(next_token, str) or not next_token:
                    raise ValueError("TAXII pagination response is invalid")
            else:
                raise ValueError("TAXII pagination limit exceeded")

            deferred = 0
            for obj in objects:
                if items_processed >= self._max_items_per_poll:
                    deferred += 1
                    continue
                if obj.get("type") == "indicator":
                    pattern = obj.get("pattern", "")
                    # Extract IOC value from STIX pattern
                    # Simple extraction for common patterns
                    import re
                    ip_match = re.search(r"ipv4-addr:value\s*=\s*'([^']+)'", pattern)
                    domain_match = re.search(r"domain-name:value\s*=\s*'([^']+)'", pattern)
                    hash_match = re.search(r"file:hashes\.\S+\s*=\s*'([^']+)'", pattern)
                    url_match = re.search(r"url:value\s*=\s*'([^']+)'", pattern)

                    ioc_value = ""
                    ioc_type = ""
                    if ip_match:
                        ioc_value = ip_match.group(1)
                        ioc_type = "ip"
                    elif domain_match:
                        ioc_value = domain_match.group(1)
                        ioc_type = "domain"
                    elif hash_match:
                        ioc_value = hash_match.group(1)
                        ioc_type = "hash"
                    elif url_match:
                        ioc_value = url_match.group(1)
                        ioc_type = "url"

                    if ioc_value:
                        item_url = f"taxii:{obj.get('id', '')}"
                        existing = self._conn.execute(
                            "SELECT 1 FROM seen_items WHERE feed_name = ? AND item_url = ?",
                            (feed["name"], item_url),
                        ).fetchone()
                        if not existing:
                            if self._ingestor:
                                import tempfile
                                with tempfile.TemporaryDirectory(prefix="blackonyx_taxii_") as tmp:
                                    item_path = Path(tmp) / f"{hashlib.sha256(item_url.encode()).hexdigest()}.txt"
                                    item_path.write_text(
                                        f"STIX indicator {obj.get('id', '')}\n{ioc_type}: {ioc_value}\n{pattern}",
                                        encoding="utf-8",
                                    )
                                    await asyncio.to_thread(
                                        self._ingestor.process_file,
                                        str(item_path), feed["collection"],
                                    )
                            with self._lock:
                                self._conn.execute(
                                    "INSERT OR IGNORE INTO seen_items (feed_name, item_url) VALUES (?, ?)",
                                    (feed["name"], item_url),
                                )
                                self._conn.commit()
                            items_processed += 1
                            iocs_extracted += 1

            with self._lock:
                self._conn.execute(
                    "UPDATE feeds SET last_poll = ? WHERE name = ?",
                    (datetime.now().isoformat(), feed["name"]),
                )
                self._conn.commit()

            taxii_result: dict[str, Any] = {
                "feed": feed["name"],
                "items_available": len(objects),
                "items_processed": items_processed,
                "iocs_extracted": iocs_extracted,
            }
            if deferred:
                taxii_result["items_deferred"] = deferred
            return taxii_result
        except (FeedFetchError, ValueError) as exc:
            logger.warning("TAXII poll failed for %s: %s", feed["name"], exc)
            return {"feed": feed["name"], "error": str(exc)}
        except Exception as exc:
            logger.exception("TAXII poll failed for %s", feed["name"])
            return {"feed": feed["name"], "error": f"Feed poll failed: {type(exc).__name__}"}

    async def poll_all(self) -> dict[str, dict]:
        """Poll every enabled feed that is due, reporting the ones that are not."""
        now = datetime.now()
        feeds = []
        skipped: dict[str, dict[str, Any]] = {}
        for feed in self.list_feeds():
            if not feed.get("enabled"):
                skipped[feed["name"]] = {"feed": feed["name"], "skipped": "Feed is disabled"}
                continue
            last_poll = datetime.fromisoformat(feed["last_poll"]) if feed.get("last_poll") else None
            if last_poll and (now - last_poll).total_seconds() < feed["poll_interval_minutes"] * 60:
                due = last_poll + timedelta(minutes=feed["poll_interval_minutes"])
                skipped[feed["name"]] = {
                    "feed": feed["name"],
                    "skipped": f"Not due until {due.isoformat(timespec='minutes')}",
                }
                continue
            feeds.append(feed)
        semaphore = asyncio.Semaphore(self._max_concurrent)
        async def poll(feed: dict[str, Any]) -> tuple[str, dict[str, Any]]:
            async with semaphore:
                return feed["name"], await self.poll_feed(feed["name"])
        polled = dict(await asyncio.gather(*(poll(feed) for feed in feeds)))
        return {**skipped, **polled}

    def start_scheduler(self, interval_seconds: int = 60) -> None:
        """Start a background scheduler to poll feeds periodically."""
        def _scheduler():
            while not self._scheduler_stop.is_set():
                try:
                    asyncio.run(self.poll_all())
                except Exception as e:
                    logger.error(f"Feed scheduler error: {e}")
                self._scheduler_stop.wait(interval_seconds)

        if not self._scheduler_thread or not self._scheduler_thread.is_alive():
            self._scheduler_stop.clear()
            self._scheduler_thread = threading.Thread(target=_scheduler, daemon=True)
            self._scheduler_thread.start()

    def close(self) -> None:
        """Close the database connection."""
        self._scheduler_stop.set()
        if self._scheduler_thread:
            self._scheduler_thread.join(timeout=5)
        if self._conn:
            self._conn.close()

    async def _validate_remote_url(self, value: str) -> tuple[str, int, list[str]]:
        """Resolve and validate a feed destination for a pinned connection."""
        import socket
        parsed = urlparse(value)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
            raise ValueError("Feed URLs must use HTTPS")
        hostname = parsed.hostname.casefold()
        if self._allowed_hosts and hostname not in self._allowed_hosts:
            raise ValueError("Feed hostname is not allowlisted")
        infos = await asyncio.to_thread(socket.getaddrinfo, hostname, parsed.port or 443)
        addresses: list[str] = []
        for info in infos:
            address = str(info[4][0]).split("%", 1)[0]
            if not ipaddress.ip_address(address).is_global:
                raise ValueError("Feed hostname resolves to a non-public address")
            if address not in addresses:
                addresses.append(address)
        if not addresses:
            raise ValueError("Feed hostname did not resolve")
        return hostname, parsed.port or 443, addresses

    async def _safe_fetch(
        self, value: str, auth: Any = None, headers: dict[str, str] | None = None,
    ) -> bytes:
        import httpx
        async with httpx.AsyncClient(
            timeout=30, follow_redirects=False, auth=auth, trust_env=False
        ) as client:
            current = value
            for _ in range(4):
                hostname, port, addresses = await self._validate_remote_url(current)
                parsed = urlparse(current)
                address = addresses[0]
                pinned_host = f"[{address}]" if ":" in address else address
                pinned_url = parsed._replace(netloc=f"{pinned_host}:{port}").geturl()
                request_headers = dict(DEFAULT_FETCH_HEADERS)
                request_headers.update(headers or {})
                request_headers["Host"] = hostname if port == 443 else f"{hostname}:{port}"
                try:
                    async with client.stream(
                        "GET",
                        pinned_url,
                        headers=request_headers,
                        extensions={"sni_hostname": hostname},
                    ) as response:
                        if response.is_redirect:
                            from urllib.parse import urljoin
                            location = response.headers.get("location")
                            if not location:
                                raise FeedFetchError(
                                    f"{hostname} sent a redirect without a location header",
                                )
                            current = urljoin(current, location)
                            continue
                        if response.status_code >= 400:
                            raise FeedFetchError(
                                f"{hostname} returned HTTP {response.status_code} "
                                f"{response.reason_phrase or ''}".strip(),
                            )
                        length = response.headers.get("content-length")
                        if length and int(length) > self._max_response_bytes:
                            raise FeedFetchError(
                                f"{hostname} response exceeds the "
                                f"{self._max_response_bytes} byte limit",
                            )
                        body = bytearray()
                        async for chunk in response.aiter_bytes():
                            body.extend(chunk)
                            if len(body) > self._max_response_bytes:
                                raise FeedFetchError(
                                    f"{hostname} response exceeds the "
                                    f"{self._max_response_bytes} byte limit",
                                )
                        return bytes(body)
                except httpx.TimeoutException as exc:
                    raise FeedFetchError(f"{hostname} timed out after 30s") from exc
                except httpx.TransportError as exc:
                    raise FeedFetchError(
                        f"Could not connect to {hostname}: {type(exc).__name__}",
                    ) from exc
        raise FeedFetchError("Feed exceeded the redirect limit (4 hops)")
