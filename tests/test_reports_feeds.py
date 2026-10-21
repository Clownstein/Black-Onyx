"""Tests for report generator and feed manager."""

import pytest
import tempfile

from black_onyx.threat.report_generator import ReportGenerator


class TestReportGenerator:
    def test_generate_markdown_basic(self):
        gen = ReportGenerator(llm_provider=None)
        iocs = {"ipv4": ["1.2.3.4"], "domain": ["evil.com"]}
        report = gen.generate_markdown_report(title="Test Report", iocs=iocs)
        assert "# Test Report" in report
        assert "1.2.3.4" in report
        assert "evil.com" in report
        assert "## Indicators of Compromise" in report
        assert "## Recommendations" in report

    def test_generate_markdown_with_enrichments(self):
        gen = ReportGenerator(llm_provider=None)
        iocs = {"ipv4": ["1.2.3.4"]}
        enrichments = [
            {"provider": "VirusTotal", "ioc_value": "1.2.3.4", "malicious": True, "confidence": 0.9, "tags": ["malware"]},
        ]
        report = gen.generate_markdown_report(title="Enriched Report", iocs=iocs, enrichments=enrichments)
        assert "## Enrichment Results" in report
        assert "VirusTotal" in report
        assert "malware" in report

    def test_generate_markdown_with_mitre(self):
        gen = ReportGenerator(llm_provider=None)
        iocs = {"ipv4": ["1.2.3.4"]}
        techniques = [
            {"technique_id": "T1059", "name": "Command and Scripting Interpreter", "tactic": ["execution"]},
        ]
        report = gen.generate_markdown_report(title="MITRE Report", iocs=iocs, mitre_techniques=techniques)
        assert "## MITRE ATT&CK Mapping" in report
        assert "T1059" in report

    def test_markdown_to_html(self):
        gen = ReportGenerator(llm_provider=None)
        md = "# Title\n\nSome **bold** text."
        html = gen.markdown_to_html(md)
        assert "<html" in html.lower()
        assert "Title" in html

    def test_empty_iocs(self):
        gen = ReportGenerator(llm_provider=None)
        report = gen.generate_markdown_report(title="Empty", iocs={})
        assert "# Empty" in report
        assert "## Indicators of Compromise" in report


class TestFeedManager:
    def test_add_and_list_feed(self):
        from black_onyx.feeds.feed_manager import FeedManager
        with tempfile.TemporaryDirectory() as d:
            mgr = FeedManager(persist_dir=d, allowed_hosts=["example.com"])
            try:
                mgr.add_feed(name="TestFeed", url="https://example.com/rss", feed_type="rss")
                feeds = mgr.list_feeds()
                assert len(feeds) == 1
                assert feeds[0]["name"] == "TestFeed"
            finally:
                mgr.close()

    def test_remove_feed(self):
        from black_onyx.feeds.feed_manager import FeedManager
        with tempfile.TemporaryDirectory() as d:
            mgr = FeedManager(persist_dir=d, allowed_hosts=["example.com"])
            try:
                mgr.add_feed(name="TestFeed", url="https://example.com/rss")
                mgr.remove_feed("TestFeed")
                feeds = mgr.list_feeds()
                assert len(feeds) == 0
            finally:
                mgr.close()

    def test_add_feed_from_dict(self):
        from black_onyx.feeds.feed_manager import FeedManager
        with tempfile.TemporaryDirectory() as d:
            mgr = FeedManager(persist_dir=d, allowed_hosts=["example.com"])
            try:
                mgr.add_feed_from_dict({
                    "name": "DictFeed",
                    "url": "https://example.com/rss",
                    "feed_type": "rss",
                    "collection": "all-knowledge",
                })
                feeds = mgr.list_feeds()
                assert len(feeds) == 1
                assert feeds[0]["name"] == "DictFeed"
            finally:
                mgr.close()

    def test_empty_allowlist_permits_https_hosts(self):
        from black_onyx.feeds.feed_manager import FeedManager
        with tempfile.TemporaryDirectory() as d:
            mgr = FeedManager(persist_dir=d, allowed_hosts=[])
            try:
                mgr.add_feed(name="Open", url="https://example.com/rss")
                assert len(mgr.list_feeds()) == 1
            finally:
                mgr.close()

    def test_feed_requires_allowlist_and_secret_reference(self):
        from black_onyx.feeds.feed_manager import FeedManager
        with tempfile.TemporaryDirectory() as d:
            mgr = FeedManager(persist_dir=d, allowed_hosts=["approved.example"])
            try:
                with pytest.raises(ValueError, match="allowlisted"):
                    mgr.add_feed(name="Blocked", url="https://example.com/rss")
                with pytest.raises(ValueError, match="password_env"):
                    mgr.add_feed(
                        name="Taxii", url="https://approved.example/taxii", feed_type="taxii",
                        config={"password": "plaintext"},
                    )
            finally:
                mgr.close()

    @pytest.mark.asyncio
    async def test_feed_rejects_private_dns_answers(self, monkeypatch):
        from black_onyx.feeds.feed_manager import FeedManager
        import socket
        with tempfile.TemporaryDirectory() as d:
            mgr = FeedManager(persist_dir=d, allowed_hosts=["approved.example"])
            monkeypatch.setattr(
                socket, "getaddrinfo",
                lambda *args, **kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))],
            )
            try:
                with pytest.raises(ValueError, match="non-public"):
                    await mgr._validate_remote_url("https://approved.example/feed")
            finally:
                mgr.close()

    @pytest.mark.asyncio
    async def test_feed_validation_returns_only_pinnable_public_addresses(self, monkeypatch):
        from black_onyx.feeds.feed_manager import FeedManager
        import socket
        mgr = FeedManager(allowed_hosts=["approved.example"])
        monkeypatch.setattr(
            socket, "getaddrinfo",
            lambda *args, **kwargs: [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443)),
            ],
        )
        try:
            hostname, port, addresses = await mgr._validate_remote_url(
                "https://approved.example/feed"
            )
            assert (hostname, port, addresses) == (
                "approved.example", 443, ["93.184.216.34"]
            )
        finally:
            mgr.close()


class TestWebhookManager:
    def test_create_authenticate_and_revoke(self):
        from black_onyx.threat.webhook_manager import WebhookManager
        with tempfile.TemporaryDirectory() as d:
            mgr = WebhookManager(persist_dir=d)
            try:
                created = mgr.create_webhook("siem")
                assert created["token"]
                assert mgr.authenticate(created["token"])["name"] == "siem"
                assert mgr.authenticate("wrong-token") is None
                assert mgr.delete_webhook(created["webhook_id"])
                assert mgr.authenticate(created["token"]) is None
            finally:
                mgr.close()
