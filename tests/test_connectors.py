"""Tests for the detection connector framework: manager CRUD/polling and the
generic REST connector's config-driven pagination/auth."""

from __future__ import annotations

import asyncio
import tempfile
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from black_onyx.connectors.base import DetectionPullResult
from black_onyx.connectors.connector_manager import DetectionConnectorManager
from black_onyx.connectors.factory import create_detection_connector
from black_onyx.models.data_model import DataModel


@pytest.fixture
def tmp_dir():
    with tempfile.TemporaryDirectory() as d:
        yield d


def _public_dns():
    return patch(
        "black_onyx.net.safe_url.socket.getaddrinfo",
        return_value=[(2, 1, 6, "", ("93.184.216.34", 443))],
    )


class TestDetectionConnectorManagerCRUD:
    def test_listing_connectors_does_not_construct_ingestor(self, tmp_dir):
        factory = MagicMock(side_effect=AssertionError("ingestor should stay lazy"))
        mgr = DetectionConnectorManager(persist_dir=tmp_dir, ingestor_factory=factory)
        try:
            assert mgr.list_connectors() == []
            factory.assert_not_called()
        finally:
            mgr.close()

    def test_add_and_list_connector(self, tmp_dir):
        with _public_dns():
            mgr = DetectionConnectorManager(persist_dir=tmp_dir)
            try:
                created = mgr.add_connector(
                    name="TestFalcon", connector_type="generic_rest",
                    base_url="https://api.example.com",
                    config={"detections_path": "/alerts", "auth": {"type": "api_key_header"}},
                    credential_env={"api_key": "TEST_API_KEY"},
                )
                assert created["name"] == "TestFalcon"
                assert created["collection"] == "detect-TestFalcon"
                assert created["enabled"] is True
                connectors = mgr.list_connectors()
                assert len(connectors) == 1
                assert connectors[0]["id"] == created["id"]
            finally:
                mgr.close()

    def test_add_connector_rejects_raw_secrets(self, tmp_dir):
        """Mirrors FeedManager.add_feed's rejection of a raw "password" in
        config — real credential values must only ever live in os.environ,
        referenced here by env var name, never copied into config_json."""
        with _public_dns():
            mgr = DetectionConnectorManager(persist_dir=tmp_dir)
            try:
                with pytest.raises(ValueError, match="raw secrets"):
                    mgr.add_connector(
                        name="Bad", connector_type="generic_rest",
                        base_url="https://api.example.com",
                        config={"api_key": "leaked-value"},
                    )
                assert mgr.list_connectors() == []
            finally:
                mgr.close()

    def test_add_connector_rejects_non_allowlisted_host(self, tmp_dir):
        with _public_dns():
            mgr = DetectionConnectorManager(persist_dir=tmp_dir, allowed_hosts=["api.allowed.com"])
            try:
                with pytest.raises(ValueError, match="not allowlisted"):
                    mgr.add_connector(
                        name="Bad", connector_type="generic_rest", base_url="https://api.example.com",
                    )
            finally:
                mgr.close()

    def test_update_connector_enabled_and_interval(self, tmp_dir):
        with _public_dns():
            mgr = DetectionConnectorManager(persist_dir=tmp_dir)
            try:
                created = mgr.add_connector(
                    name="TestConn", connector_type="generic_rest", base_url="https://api.example.com",
                )
                updated = mgr.update_connector(created["id"], enabled=False, poll_interval_minutes=30)
                assert updated["enabled"] is False
                assert updated["poll_interval_minutes"] == 30
            finally:
                mgr.close()

    def test_delete_connector(self, tmp_dir):
        with _public_dns():
            mgr = DetectionConnectorManager(persist_dir=tmp_dir)
            try:
                created = mgr.add_connector(
                    name="TestConn", connector_type="generic_rest", base_url="https://api.example.com",
                )
                assert mgr.delete_connector(created["id"]) is True
                assert mgr.list_connectors() == []
            finally:
                mgr.close()

    def test_default_collection_name_derived_from_connector_name(self, tmp_dir):
        with _public_dns():
            mgr = DetectionConnectorManager(persist_dir=tmp_dir)
            try:
                created = mgr.add_connector(
                    name="My SIEM! Prod", connector_type="generic_rest", base_url="https://api.example.com",
                )
                assert created["collection"].startswith("detect-")
            finally:
                mgr.close()


class TestDetectionConnectorManagerPolling:
    def test_poll_connector_ingests_and_advances_cursor(self, tmp_dir):
        """End-to-end: poll -> normalize -> ingestor.process_document ->
        watchlist check, exactly the same pipeline any other ingestion goes
        through — this is the test that guards against a parallel data path
        being reintroduced."""
        with _public_dns():
            embedding_model = MagicMock()
            embedding_model.get_embedding_dim.return_value = 8
            embedding_model.encode_single.return_value = [0.1] * 8
            qdrant_store = MagicMock()
            qdrant_store.stable_id = staticmethod(lambda key, idx=0: abs(hash(key)) % (2**32))
            watchlist_manager = MagicMock()
            watchlist_manager.check_iocs.return_value = []

            from black_onyx.pipeline.ingestor import Ingestor
            ingestor = Ingestor(
                embedding_model=embedding_model, qdrant_store=qdrant_store,
                watchlist_manager=watchlist_manager,
            )

            mgr = DetectionConnectorManager(persist_dir=tmp_dir, ingestor=ingestor)
            try:
                created = mgr.add_connector(
                    name="TestConn", connector_type="generic_rest", base_url="https://api.example.com",
                    config={
                        "detections_path": "/alerts", "auth": {"type": "api_key_header"},
                        "response_items_path": "items", "id_path": "id",
                        "field_map": {"title": "summary", "ip_addresses": "ip"},
                    },
                    credential_env={"api_key": "TEST_API_KEY"},
                )

                fake_connector = MagicMock()
                fake_connector.authenticate = AsyncMock()
                fake_connector.pull_detections = AsyncMock(return_value=DetectionPullResult(
                    detections=[
                        {"id": "d1", "summary": "Alert one", "ip": "203.0.113.5"},
                        {"id": "d2", "summary": "Alert two", "ip": "203.0.113.6"},
                    ],
                    next_cursor="cur-2", raw_count=2,
                ))
                fake_connector.normalize = MagicMock(side_effect=lambda raw: DataModel(
                    source_file=f"connector:TestConn:{raw['id']}", title=raw["summary"],
                    ip_addresses=[raw["ip"]], ioc_status="new",
                ))

                with patch(
                    "black_onyx.connectors.connector_manager.create_detection_connector",
                    return_value=fake_connector,
                ):
                    result = asyncio.run(mgr.poll_connector(created["id"]))

                assert result == {
                    "connector": "TestConn", "processed": 2, "skipped": 0,
                    "errors": 0, "raw_count": 2,
                }
                assert mgr._get_cursor(created["id"]) == "cur-2"
                assert qdrant_store.upsert_single.call_count == 2
                assert watchlist_manager.check_iocs.call_count == 2

                row = mgr.get_connector(created["id"])
                assert row["last_poll_status"] == "ok"
                assert row["last_poll_error"] is None
                assert row["last_success_at"] is not None
            finally:
                mgr.close()

    def test_repolling_the_same_detections_does_not_re_alert(self, tmp_dir):
        """Regression: re-seeing a detection is normal (offset pagination
        restarts at 0, `since` windows overlap, admins re-poll by hand). The
        Qdrant upsert is idempotent, but `_observe_iocs` -> `check_iocs`
        INSERTs a fresh alert row every time, so without dedupe every poll
        cycle raised duplicate watchlist alerts and re-embedded the same text."""
        with _public_dns():
            embedding_model = MagicMock()
            embedding_model.get_embedding_dim.return_value = 8
            embedding_model.encode_single.return_value = [0.1] * 8
            qdrant_store = MagicMock()
            qdrant_store.stable_id = staticmethod(lambda key, idx=0: abs(hash(key)) % (2**32))
            watchlist_manager = MagicMock()
            watchlist_manager.check_iocs.return_value = []

            from black_onyx.pipeline.ingestor import Ingestor
            ingestor = Ingestor(
                embedding_model=embedding_model, qdrant_store=qdrant_store,
                watchlist_manager=watchlist_manager,
            )
            mgr = DetectionConnectorManager(persist_dir=tmp_dir, ingestor=ingestor)
            try:
                created = mgr.add_connector(
                    name="Repeat", connector_type="generic_rest", base_url="https://api.example.com",
                )
                connector = MagicMock()
                connector.authenticate = AsyncMock()
                connector.pull_detections = AsyncMock(return_value=DetectionPullResult(
                    detections=[{"id": "d1"}, {"id": "d2"}], next_cursor=None, raw_count=2,
                ))
                connector.normalize = MagicMock(side_effect=lambda raw: DataModel(
                    source_file=f"connector:Repeat:{raw['id']}", title="x",
                    ip_addresses=["203.0.113.5"], ioc_status="new",
                ))
                with patch.object(DetectionConnectorManager, "_build_connector", return_value=connector):
                    first = asyncio.run(mgr.poll_connector(created["id"]))
                    second = asyncio.run(mgr.poll_connector(created["id"]))

                assert first["processed"] == 2 and first["skipped"] == 0
                assert second["processed"] == 0 and second["skipped"] == 2
                # Two ingests total, not four.
                assert watchlist_manager.check_iocs.call_count == 2
                assert qdrant_store.upsert_single.call_count == 2
            finally:
                mgr.close()

    def test_failed_poll_does_not_advance_the_since_watermark(self, tmp_dir):
        """Regression: `last_poll_at` drives due-scheduling and was also being
        used as the `since` watermark, so a failed poll skipped everything the
        upstream raised between the last success and the failure."""
        with _public_dns():
            mgr = DetectionConnectorManager(persist_dir=tmp_dir)
            try:
                created = mgr.add_connector(
                    name="Watermark", connector_type="generic_rest", base_url="https://api.example.com",
                )
                ok = MagicMock()
                ok.authenticate = AsyncMock()
                ok.pull_detections = AsyncMock(return_value=DetectionPullResult(
                    detections=[], next_cursor=None, raw_count=0,
                ))
                with patch.object(DetectionConnectorManager, "_build_connector", return_value=ok):
                    asyncio.run(mgr.poll_connector(created["id"]))
                after_success = mgr.get_connector(created["id"])["last_success_at"]
                assert after_success is not None

                broken = MagicMock()
                broken.authenticate = AsyncMock()
                broken.pull_detections = AsyncMock(side_effect=RuntimeError("upstream 500"))
                with patch.object(DetectionConnectorManager, "_build_connector", return_value=broken):
                    asyncio.run(mgr.poll_connector(created["id"]))

                row = mgr.get_connector(created["id"])
                assert row["last_poll_status"] == "failed"
                # Watermark frozen at the last success...
                assert row["last_success_at"] == after_success
                # ...but the attempt timestamp advanced, so a broken connector
                # still backs off to its interval instead of hot-looping.
                assert row["last_poll_at"] != after_success
            finally:
                mgr.close()

    def test_connector_built_from_documented_request_shape(self, tmp_dir):
        """Regression: `base_url` is validated into its own column, but
        connectors read it out of `config`. A connector created the documented
        way — base_url top-level, config holding only endpoint/auth settings —
        used to raise KeyError: 'base_url' on every single poll."""
        with _public_dns():
            mgr = DetectionConnectorManager(persist_dir=tmp_dir)
            try:
                created = mgr.add_connector(
                    name="ApiShaped", connector_type="generic_rest",
                    base_url="https://api.example.com",
                    config={"detections_path": "/alerts", "auth": {"type": "api_key_header"}},
                    credential_env={"api_key": "TEST_API_KEY"},
                )
                assert "base_url" not in created["config"]
                connector = mgr._build_connector(mgr.get_connector(created["id"]))
                assert connector._base_url == "https://api.example.com"
            finally:
                mgr.close()

    def test_poll_connector_records_failure_without_raising(self, tmp_dir):
        with _public_dns():
            mgr = DetectionConnectorManager(persist_dir=tmp_dir)
            try:
                created = mgr.add_connector(
                    name="Broken", connector_type="generic_rest", base_url="https://api.example.com",
                )
                fake_connector = MagicMock()
                fake_connector.authenticate = AsyncMock()
                fake_connector.pull_detections = AsyncMock(side_effect=RuntimeError("upstream down"))
                with patch(
                    "black_onyx.connectors.connector_manager.create_detection_connector",
                    return_value=fake_connector,
                ):
                    result = asyncio.run(mgr.poll_connector(created["id"]))
                assert "error" in result
                row = mgr.get_connector(created["id"])
                assert row["last_poll_status"] == "failed"
                assert row["last_poll_error"]
            finally:
                mgr.close()

    def test_poll_connector_skips_when_disabled(self, tmp_dir):
        with _public_dns():
            mgr = DetectionConnectorManager(persist_dir=tmp_dir)
            try:
                created = mgr.add_connector(
                    name="Paused", connector_type="generic_rest", base_url="https://api.example.com",
                    enabled=False,
                )
                result = asyncio.run(mgr.poll_connector(created["id"]))
                assert result["skipped"]
            finally:
                mgr.close()

    def test_push_detections_uses_same_ingest_path(self, tmp_dir):
        """Push skips upstream pull but still normalize → process_document."""
        with _public_dns():
            embedding_model = MagicMock()
            embedding_model.get_embedding_dim.return_value = 8
            embedding_model.encode_single.return_value = [0.1] * 8
            qdrant_store = MagicMock()
            qdrant_store.stable_id = staticmethod(lambda key, idx=0: abs(hash(key)) % (2**32))
            watchlist_manager = MagicMock()
            watchlist_manager.check_iocs.return_value = []

            from black_onyx.pipeline.ingestor import Ingestor
            ingestor = Ingestor(
                embedding_model=embedding_model, qdrant_store=qdrant_store,
                watchlist_manager=watchlist_manager,
            )
            mgr = DetectionConnectorManager(persist_dir=tmp_dir, ingestor=ingestor)
            try:
                created = mgr.add_connector(
                    name="PushConn", connector_type="generic_rest",
                    base_url="https://api.example.com",
                    config={
                        "detections_path": "/alerts", "auth": {"type": "api_key_header"},
                        "response_items_path": "items", "id_path": "id",
                        "field_map": {"title": "summary", "ip_addresses": "ip"},
                    },
                    credential_env={"api_key": "TEST_API_KEY"},
                )
                fake_connector = MagicMock()
                fake_connector.normalize = MagicMock(side_effect=lambda raw: DataModel(
                    source_file=f"connector:PushConn:{raw['id']}", title=raw["summary"],
                    ip_addresses=[raw["ip"]], ioc_status="new",
                ))
                with patch(
                    "black_onyx.connectors.connector_manager.create_detection_connector",
                    return_value=fake_connector,
                ):
                    result = asyncio.run(mgr.push_detections(created["id"], [
                        {"id": "p1", "summary": "Pushed one", "ip": "203.0.113.9"},
                    ]))
                assert result["mode"] == "push"
                assert result["processed"] == 1
                assert result["raw_count"] == 1
                assert qdrant_store.upsert_single.call_count == 1
                assert fake_connector.pull_detections.call_count == 0
                row = mgr.get_connector(created["id"])
                assert row["last_poll_status"] == "ok"
            finally:
                mgr.close()

    def test_poll_all_skips_connectors_not_yet_due(self, tmp_dir):
        with _public_dns():
            mgr = DetectionConnectorManager(persist_dir=tmp_dir)
            try:
                created = mgr.add_connector(
                    name="TestConn", connector_type="generic_rest", base_url="https://api.example.com",
                    poll_interval_minutes=60,
                )
                # Simulate a poll that just happened.
                mgr._record_outcome(created["id"], "ok", None)
                result = asyncio.run(mgr.poll_all())
                assert "skipped" in result["TestConn"]
            finally:
                mgr.close()


class TestGenericRestConnectorFactory:
    def test_factory_dispatches_generic_rest(self):
        with _public_dns():
            connector = create_detection_connector(
                "generic_rest", "t", {"base_url": "https://api.example.com"}, {},
            )
            assert connector.source_type == "generic_rest"

    def test_factory_rejects_unknown_type(self):
        with pytest.raises(ValueError, match="Unknown connector type"):
            create_detection_connector("not_a_real_type", "t", {}, {})

    def test_normalize_maps_fields_and_builds_stable_source_file(self):
        with _public_dns():
            connector = create_detection_connector("generic_rest", "conn-1", {
                "base_url": "https://api.example.com",
                "field_map": {"title": "summary", "ip_addresses": "network.remoteIp"},
                "id_path": "id",
            }, {})
            data_model = connector.normalize({"id": "abc", "summary": "Suspicious login", "network": {"remoteIp": "203.0.113.7"}})
            assert data_model.title == "Suspicious login"
            assert data_model.ip_addresses == ["203.0.113.7"]
            assert data_model.source_file == "connector:conn-1:abc"
            assert data_model.ioc_status == "new"
