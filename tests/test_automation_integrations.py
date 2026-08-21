"""Tests for MISP sync, TAXII publish, and SOAR-lite playbooks."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import tempfile

from black_onyx.integrations.misp.sync_manager import MispSyncManager
from black_onyx.taxii.publish_manager import TaxiiPublishManager
from black_onyx.automation.playbook_manager import PlaybookManager
from black_onyx.automation.runner import PlaybookRunner


@pytest.fixture
def tmp_dir():
    with tempfile.TemporaryDirectory() as d:
        yield d


class TestTaxiiPublishManager:
    def test_create_collection_api_key_auth_and_list_objects(self, tmp_dir):
        mgr = TaxiiPublishManager(persist_dir=tmp_dir)
        try:
            collection = mgr.create_collection("Shared IOCs", description="Outbound STIX")
            assert collection["collection_id"]
            assert collection["title"] == "Shared IOCs"

            key = mgr.create_api_key("consumer")
            assert key["token"]
            assert key["token_prefix"] == key["token"][:8]

            principal = mgr.authenticate_key(key["token"])
            assert principal is not None
            assert principal["name"] == "consumer"
            assert mgr.authenticate_key("wrong-token") is None

            objects = [
                {
                    "type": "indicator",
                    "id": "indicator--11111111-1111-1111-1111-111111111111",
                    "pattern": "[ipv4-addr:value = '1.2.3.4']",
                    "pattern_type": "stix",
                }
            ]
            result = mgr.publish_stix_objects(collection["collection_id"], objects)
            assert result["objects_stored"] == 1

            listed = mgr.list_objects(collection["collection_id"], limit=10)
            assert len(listed) == 1
            assert listed[0]["id"] == objects[0]["id"]

            # Same STIX id in a second collection must not displace the first.
            other = mgr.create_collection("Internal")
            mgr.publish_stix_objects(other["collection_id"], objects)
            assert len(mgr.list_objects(collection["collection_id"])) == 1
            assert len(mgr.list_objects(other["collection_id"])) == 1

            assert mgr.set_api_key_enabled(key["key_id"], False) is True
            assert mgr.authenticate_key(key["token"]) is None
            assert mgr.set_api_key_enabled(key["key_id"], True) is True
            assert mgr.authenticate_key(key["token"]) is not None
            assert mgr.delete_api_key(key["key_id"]) is True
            assert mgr.authenticate_key(key["token"]) is None
        finally:
            mgr.close()


class TestPlaybookManagerAndRunner:
    def test_create_and_run_notify_webhook_mocked(self, tmp_dir):
        mgr = PlaybookManager(persist_dir=tmp_dir)
        try:
            with patch("black_onyx.net.safe_url.socket.getaddrinfo") as mock_dns:
                mock_dns.return_value = [
                    (0, 0, 0, "", ("93.184.216.34", 443)),
                ]
                endpoint = mgr.create_endpoint("default", "https://hooks.example.com/playbook")
            playbook = mgr.create_playbook(
                name="Notify on alert",
                trigger_type="manual",
                steps=[
                    {
                        "type": "notify_webhook",
                        "endpoint_id": endpoint["id"],
                    }
                ],
            )
            assert playbook["id"]
            assert playbook["enabled"] is True

            runner = PlaybookRunner(playbook_manager=mgr)
            run = mgr.start_run(playbook["id"], {"alerts": [{"ioc_type": "ip", "ioc_value": "9.9.9.9"}]})

            mock_response = AsyncMock()
            mock_response.status_code = 200
            mock_response.raise_for_status = lambda: None

            mock_client = AsyncMock()
            mock_client.__aenter__.return_value = mock_client
            mock_client.__aexit__.return_value = None
            mock_client.post = AsyncMock(return_value=mock_response)

            with patch("black_onyx.automation.runner.httpx.AsyncClient", return_value=mock_client), \
                 patch("black_onyx.net.safe_url.socket.getaddrinfo") as mock_dns:
                mock_dns.return_value = [(0, 0, 0, "", ("93.184.216.34", 443))]
                finished = asyncio.run(runner.execute_run(run["run_id"]))

            assert finished["status"] == "completed"
            assert finished["steps"][0]["status"] == "completed"
            assert finished["steps"][0]["step_type"] == "notify_webhook"
            mock_client.post.assert_awaited_once()
            call_args = mock_client.post.await_args
            assert call_args.args[0] == "https://hooks.example.com/playbook"
        finally:
            mgr.close()

    def test_enrich_step_writes_back_to_qdrant_point(self, tmp_dir):
        """_step_enrich used to only store its result in the playbook run's own
        context row — not on the IOC's actual Qdrant point. "Auto-enrich on
        watchlist match" has to mean the IOC record itself gets populated."""
        from black_onyx.enrichment.base import EnrichmentResult

        mgr = PlaybookManager(persist_dir=tmp_dir)
        try:
            playbook = mgr.create_playbook(
                name="Enrich on match", trigger_type="watchlist_alert",
                steps=[{"type": "enrich"}],
            )
            enrichment_manager = AsyncMock()
            enrichment_manager.enrich_batch.return_value = {
                "9.9.9.9": [EnrichmentResult(
                    provider="virustotal", ioc_type="ip", ioc_value="9.9.9.9",
                    malicious=True, confidence=0.9, tags=["scanner"], raw_data={},
                )],
            }
            qdrant_store = MagicMock()  # set_payload is a plain sync method

            runner = PlaybookRunner(
                playbook_manager=mgr, enrichment_manager=enrichment_manager,
                qdrant_store=qdrant_store,
            )
            run = mgr.start_run(playbook["id"], {
                "iocs": [{"ioc_type": "ip", "ioc_value": "9.9.9.9"}],
                "collection": "all-knowledge",
                "point_id": "point-42",
            })
            finished = asyncio.run(runner.execute_run(run["run_id"]))

            assert finished["status"] == "completed"
            qdrant_store.set_payload.assert_called_once()
            call_args = qdrant_store.set_payload.call_args[0]
            assert call_args[0] == "all-knowledge"
            assert call_args[1] == "point-42"
            assert "9.9.9.9" in call_args[2]["enrichment_data"]
        finally:
            mgr.close()

    def test_enrich_step_skips_write_back_without_collection_context(self, tmp_dir):
        """A manually-triggered enrich (no collection/point_id in context, e.g.
        from the IOC workbench) must not error trying to patch a Qdrant point."""
        mgr = PlaybookManager(persist_dir=tmp_dir)
        try:
            playbook = mgr.create_playbook(
                name="Manual enrich", trigger_type="manual", steps=[{"type": "enrich"}],
            )
            enrichment_manager = AsyncMock()
            enrichment_manager.enrich_batch.return_value = {}
            qdrant_store = MagicMock()
            runner = PlaybookRunner(
                playbook_manager=mgr, enrichment_manager=enrichment_manager,
                qdrant_store=qdrant_store,
            )
            run = mgr.start_run(playbook["id"], {"iocs": [{"ioc_type": "ip", "ioc_value": "9.9.9.9"}]})
            finished = asyncio.run(runner.execute_run(run["run_id"]))
            assert finished["status"] == "completed"
            qdrant_store.set_payload.assert_not_called()
        finally:
            mgr.close()

    def test_ensure_default_watchlist_enrich_playbook_is_idempotent(self, tmp_dir):
        mgr = PlaybookManager(persist_dir=tmp_dir)
        try:
            created = mgr.ensure_default_watchlist_enrich_playbook(True)
            assert created["enabled"] is True
            assert created["trigger_type"] == "watchlist_alert"
            assert created["steps"] == [{"type": "enrich"}]

            # Re-running must reuse the same playbook, not create a duplicate.
            again = mgr.ensure_default_watchlist_enrich_playbook(True)
            assert again["id"] == created["id"]
            assert len(mgr.list_playbooks()) == 1

            # Toggling off disables it rather than deleting it.
            disabled = mgr.ensure_default_watchlist_enrich_playbook(False)
            assert disabled["id"] == created["id"]
            assert disabled["enabled"] is False
            assert len(mgr.list_playbooks()) == 1

        finally:
            mgr.close()

    def test_watchlist_alert_trigger_runs_seeded_enrich_playbook_end_to_end(self, tmp_dir):
        """The gap-closing fix in ingestor.py fires handle_trigger("watchlist_alert",
        ...); this confirms that, once seeded and enabled, the auto-enrich
        playbook actually runs off that trigger and writes enrichment_data back."""
        from black_onyx.enrichment.base import EnrichmentResult

        mgr = PlaybookManager(persist_dir=tmp_dir)
        try:
            mgr.ensure_default_watchlist_enrich_playbook(True)
            enrichment_manager = AsyncMock()
            enrichment_manager.enrich_batch.return_value = {
                "203.0.113.7": [EnrichmentResult(
                    provider="abuseipdb", ioc_type="ip", ioc_value="203.0.113.7",
                    malicious=True, confidence=0.75, tags=[], raw_data={},
                )],
            }
            qdrant_store = MagicMock()
            runner = PlaybookRunner(
                playbook_manager=mgr, enrichment_manager=enrichment_manager,
                qdrant_store=qdrant_store,
            )

            results = asyncio.run(runner.handle_trigger("watchlist_alert", {
                "alerts": [{"alert_id": "a1", "ioc_type": "ip", "ioc_value": "203.0.113.7"}],
                "iocs": [{"ioc_type": "ip", "ioc_value": "203.0.113.7"}],
                "collection": "all-knowledge",
                "point_id": "point-7",
                "source": "test",
            }))

            assert len(results) == 1
            assert results[0]["status"] == "completed"
            qdrant_store.set_payload.assert_called_once_with(
                "all-knowledge", "point-7",
                {"enrichment_data": {"203.0.113.7": [enrichment_manager.enrich_batch.return_value["203.0.113.7"][0].to_dict()]}},
            )
        finally:
            mgr.close()

    def test_endpoint_rejects_private_urls(self, tmp_dir):
        mgr = PlaybookManager(persist_dir=tmp_dir)
        try:
            with pytest.raises(ValueError, match="HTTPS"):
                mgr.create_endpoint("loopback-http", "http://127.0.0.1/hook")
            with patch("black_onyx.net.safe_url.socket.getaddrinfo") as mock_dns:
                mock_dns.return_value = [(0, 0, 0, "", ("127.0.0.1", 443))]
                with pytest.raises(ValueError, match="non-public"):
                    mgr.create_endpoint("loopback", "https://127.0.0.1/hook")
            with patch("black_onyx.net.safe_url.socket.getaddrinfo") as mock_dns:
                mock_dns.return_value = [(0, 0, 0, "", ("169.254.169.254", 443))]
                with pytest.raises(ValueError, match="non-public"):
                    mgr.create_endpoint("metadata", "https://metadata.example/latest")
        finally:
            mgr.close()


class TestMispSyncManager:
    def test_configure_and_status_without_network(self, tmp_dir):
        mgr = MispSyncManager(persist_dir=tmp_dir)
        try:
            status = mgr.get_status()
            assert status["configured"] is False
            assert status["status"] == "not configured"

            with patch("black_onyx.net.safe_url.socket.getaddrinfo") as mock_dns:
                mock_dns.return_value = [
                    (0, 0, 0, "", ("93.184.216.34", 443)),
                ]
                configured = mgr.configure(
                    url="https://example.com",
                    api_key_env="MISP_API_KEY",
                    collection="all-knowledge",
                    enabled=True,
                )
            assert configured["url"] == "https://example.com"
            assert configured["api_key_present"] is False
            assert configured["configured"] is False
            assert configured["status"] == "not configured"
            assert configured["enabled"] is True
            assert configured["collection"] == "all-knowledge"
        finally:
            mgr.close()
