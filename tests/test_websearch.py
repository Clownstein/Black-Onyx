"""Tests for web-search orchestration and collection naming helpers."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from black_onyx.core.collections import feed_collection_name, sanitize_collection_name
from black_onyx.websearch.orchestrator import (
    WebSearchOrchestrator,
    _extract_json,
    _truncate,
)
from black_onyx.websearch.persist import _content_hash, _point_id, persist_web_document


class TestExtractJson:
    def test_plain_object(self):
        assert _extract_json('{"tool":"web_search","args":{"query":"x"}}')["tool"] == "web_search"

    def test_fenced_json(self):
        text = '```json\n{"final":true,"answer":"ok"}\n```'
        assert _extract_json(text)["answer"] == "ok"

    def test_embedded_object(self):
        text = 'Sure.\n{"tool":"scrape_url","args":{"url":"https://example.com"}}\n'
        assert _extract_json(text)["tool"] == "scrape_url"

    def test_invalid(self):
        assert _extract_json("not json") is None


class TestTruncate:
    def test_short_unchanged(self):
        assert _truncate("hello", 100) == "hello"

    def test_long_truncated(self):
        value = _truncate("x" * 100, 40)
        assert value.endswith("…[truncated]")
        assert len(value) <= 40


class TestCollectionNames:
    def test_sanitize(self):
        assert sanitize_collection_name(" My Feed!! ") == "My-Feed"

    def test_feed_prefix(self):
        assert feed_collection_name("CISA Alerts") == "feed-CISA-Alerts"


class TestPersistIds:
    def test_point_id_stable(self):
        assert _point_id("https://example.com", 0) == _point_id("https://example.com", 0)
        assert _point_id("https://example.com", 0) != _point_id("https://example.com", 1)


class TestPersistDedupe:
    def _service(self, stored_payload: dict | None):
        record = SimpleNamespace(payload=stored_payload) if stored_payload else None
        qdrant_store = MagicMock()
        qdrant_store.get_point.return_value = record
        embedding_model = MagicMock()
        embedding_model.encode.return_value = [[0.1, 0.2, 0.3]]
        return SimpleNamespace(
            ensure_collection=MagicMock(),
            qdrant_store=qdrant_store,
            embedding_model=embedding_model,
        )

    def _persist(self, service, body: str = "Reused body"):
        return persist_web_document(
            service=service,
            collection="web-search",
            url="https://example.com/page",
            title="Page",
            body_text=body,
            source="firecrawl",
        )

    def test_persists_when_no_existing_point(self):
        service = self._service(None)
        sources = self._persist(service)
        assert len(sources) == 1
        service.qdrant_store.upsert.assert_called_once()
        assert sources[0]["payload"]["content_hash"] == _content_hash("Reused body")

    def test_reuses_recent_identical_content(self):
        stored = {
            "content_hash": _content_hash("Reused body"),
            "fetched_at": datetime.now(timezone.utc).isoformat(),
            "total_chunks": 1,
            "body_text": "Reused body",
        }
        service = self._service(stored)
        sources = self._persist(service)
        assert len(sources) == 1
        assert sources[0]["payload"] is stored
        service.qdrant_store.upsert.assert_not_called()
        service.embedding_model.encode.assert_not_called()

    def test_refetches_when_cache_is_stale(self):
        stored = {
            "content_hash": _content_hash("Reused body"),
            "fetched_at": (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat(),
            "total_chunks": 1,
        }
        service = self._service(stored)
        self._persist(service)
        service.qdrant_store.upsert.assert_called_once()

    def test_refetches_when_content_changed(self):
        stored = {
            "content_hash": _content_hash("Old body"),
            "fetched_at": datetime.now(timezone.utc).isoformat(),
            "total_chunks": 1,
        }
        service = self._service(stored)
        self._persist(service)
        service.qdrant_store.upsert.assert_called_once()


class TestOrchestratorTools:
    def _orchestrator(self, api_key: str = "") -> WebSearchOrchestrator:
        settings = SimpleNamespace(
            web_search=SimpleNamespace(
                searxng_url="http://searxng:8080",
                max_results=3,
                max_tool_rounds=2,
                scrape_top_k=1,
                timeout_seconds=5,
                collection="web-search",
                firecrawl_api_key_env="FIRECRAWL_API_KEY",
            ),
            get_api_key=lambda _name: api_key,
            llm=SimpleNamespace(rag=SimpleNamespace(system_prompt="sys")),
        )
        service = SimpleNamespace(settings=settings)
        llm = MagicMock()
        return WebSearchOrchestrator(service=service, llm=llm, session_id="s1")

    def test_scrape_unavailable_without_key(self):
        orch = self._orchestrator(api_key="")
        summary, sources = orch._run_scrape("https://example.com")
        assert "Scrape unavailable" in summary
        assert sources == []

    def test_web_search_includes_body_in_tool_result(self):
        orch = self._orchestrator(api_key="")
        with patch(
            "black_onyx.websearch.orchestrator.searxng.search",
            return_value=[{
                "title": "Example",
                "url": "https://example.com/a",
                "snippet": "Snippet about malware",
            }],
        ), patch(
            "black_onyx.websearch.orchestrator.persist_web_document",
            return_value=[{"id": "1", "payload": {}, "collection": "web-search"}],
        ):
            summary, sources = orch._run_web_search("malware")
        assert "Snippet about malware" in summary
        assert "Content (untrusted):" in summary
        assert sources

    def test_scrape_includes_body_in_tool_result(self):
        orch = self._orchestrator(api_key="fc-key")
        with patch(
            "black_onyx.websearch.orchestrator.firecrawl.scrape_url",
            return_value={"title": "Page", "markdown": "Full page body about APT29"},
        ), patch(
            "black_onyx.websearch.orchestrator.persist_web_document",
            return_value=[{"id": "2", "payload": {}, "collection": "web-search"}],
        ):
            summary, sources = orch._run_scrape("https://example.com/b", query="apt")
        assert "Full page body about APT29" in summary
        assert "Content (untrusted):" in summary
        assert sources
