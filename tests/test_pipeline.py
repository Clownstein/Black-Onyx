"""Tests for the pipeline — progress tracker, checkpoint manager, and the
ingestor's watchlist/playbook trigger wiring."""

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

from black_onyx.pipeline.checkpoint import CheckpointManager
from black_onyx.pipeline.ingestor import Ingestor
from black_onyx.pipeline.progress import ProgressTracker


class TestProgressTracker:
    def test_initial_state(self):
        tracker = ProgressTracker(total_files=10)
        status = tracker.get_status()
        assert status["processed"] == 0
        assert status["total"] == 10
        assert status["errors"] == 0

    def test_file_done(self):
        tracker = ProgressTracker(total_files=5)
        tracker.on_file_start("/test/file.txt")
        tracker.on_file_done("/test/file.txt", chunks=3, duration_ms=100.0)
        status = tracker.get_status()
        assert status["processed"] == 1
        assert status["total_chunks"] == 3

    def test_file_error(self):
        tracker = ProgressTracker(total_files=5)
        tracker.on_file_error("/test/bad.txt", "Parse error")
        status = tracker.get_status()
        assert status["errors"] == 1
        assert status["processed"] == 1

    def test_callback(self):
        events: list[dict] = []
        tracker = ProgressTracker(total_files=5, callback=lambda e: events.append(e))
        tracker.on_file_start("/test/file.txt")
        tracker.on_file_done("/test/file.txt", chunks=2, duration_ms=50.0)
        assert len(events) >= 2
        assert events[0]["event"] == "file_start"
        assert events[1]["event"] == "file_done"

    def test_stop(self):
        tracker = ProgressTracker()
        assert not tracker.stopped
        tracker.stop()
        assert tracker.stopped


class TestCheckpointManager:
    def test_mark_and_check(self, tmp_path: Path):
        mgr = CheckpointManager(checkpoint_dir=str(tmp_path / "checkpoints"))
        assert not mgr.is_processed("/test/file.txt", 0, "test-collection")
        mgr.mark_processed("/test/file.txt", 0, "test-collection")
        assert mgr.is_processed("/test/file.txt", 0, "test-collection")
        mgr.close()

    def test_different_collections(self, tmp_path: Path):
        mgr = CheckpointManager(checkpoint_dir=str(tmp_path / "checkpoints"))
        mgr.mark_processed("/test/file.txt", 0, "collection-a")
        assert mgr.is_processed("/test/file.txt", 0, "collection-a")
        # Different collection should not be marked
        assert not mgr.is_processed("/test/file.txt", 0, "collection-b")
        mgr.close()

    def test_reset(self, tmp_path: Path):
        mgr = CheckpointManager(checkpoint_dir=str(tmp_path / "checkpoints"))
        mgr.mark_processed("/test/file.txt", 0, "test")
        assert mgr.is_processed("/test/file.txt", 0, "test")
        mgr.reset("test")
        assert not mgr.is_processed("/test/file.txt", 0, "test")
        mgr.close()

    def test_run_tracking(self, tmp_path: Path):
        mgr = CheckpointManager(checkpoint_dir=str(tmp_path / "checkpoints"))
        mgr.start_run("run-1", "/data", "test-collection", total_files=10)
        mgr.complete_run("run-1", processed_files=8)
        mgr.close()


class TestObserveIocsPlaybookTrigger:
    """`_observe_iocs` used to only feed the watchlist manager — the webhook
    ingest route additionally fired `playbook_runner.handle_trigger`, but
    ordinary file/feed ingestion did not, so a playbook wired to
    `watchlist_alert` never ran for anything except webhook-sourced IOCs.
    These tests cover the fix that closes that asymmetry."""

    PAYLOAD = {"ip_addresses": ["203.0.113.7"], "domains": ["bad.example.com"]}

    def _ingestor(self, watchlist_manager, playbook_runner=None) -> Ingestor:
        return Ingestor(
            embedding_model=MagicMock(),
            watchlist_manager=watchlist_manager,
            playbook_runner=playbook_runner,
        )

    def test_fires_watchlist_alert_trigger_on_match(self):
        alerts = [{"alert_id": "a1", "ioc_type": "ip", "ioc_value": "203.0.113.7"}]
        watchlist_manager = MagicMock()
        watchlist_manager.check_iocs.return_value = alerts
        playbook_runner = MagicMock()
        playbook_runner.handle_trigger = AsyncMock(return_value=[])

        ingestor = self._ingestor(watchlist_manager, playbook_runner)
        ingestor._observe_iocs(self.PAYLOAD, "all-knowledge", "point-1", "test-source")

        playbook_runner.handle_trigger.assert_called_once()
        trigger_type, context = playbook_runner.handle_trigger.call_args[0]
        assert trigger_type == "watchlist_alert"
        assert context["alerts"] == alerts
        assert context["collection"] == "all-knowledge"
        assert context["point_id"] == "point-1"
        assert context["source"] == "test-source"

    def test_trigger_carries_only_matched_iocs_not_the_whole_document(self):
        """PlaybookRunner._collect_iocs prefers context["iocs"], so passing the
        full extraction would make a single watchlist hit enrich every
        indicator in the document against every provider — the paid-API quota
        burn `enrichment.auto_enrich_on_match` promises to avoid. The payload
        here has an ip and a domain; only the ip matched."""
        alerts = [{"alert_id": "a1", "ioc_type": "ip", "ioc_value": "203.0.113.7"}]
        watchlist_manager = MagicMock()
        watchlist_manager.check_iocs.return_value = alerts
        playbook_runner = MagicMock()
        playbook_runner.handle_trigger = AsyncMock(return_value=[])

        ingestor = self._ingestor(watchlist_manager, playbook_runner)
        ingestor._observe_iocs(self.PAYLOAD, "all-knowledge", "point-1", "test-source")

        _, context = playbook_runner.handle_trigger.call_args[0]
        assert context["iocs"] == [{"ioc_type": "ip", "ioc_value": "203.0.113.7"}]
        assert not any(item["ioc_value"] == "bad.example.com" for item in context["iocs"])

    def test_trigger_deduplicates_an_ioc_matched_by_several_watchlists(self):
        alerts = [
            {"alert_id": "a1", "watchlist_name": "APT", "ioc_type": "ip", "ioc_value": "203.0.113.7"},
            {"alert_id": "a2", "watchlist_name": "Ransomware", "ioc_type": "ip", "ioc_value": "203.0.113.7"},
        ]
        watchlist_manager = MagicMock()
        watchlist_manager.check_iocs.return_value = alerts
        playbook_runner = MagicMock()
        playbook_runner.handle_trigger = AsyncMock(return_value=[])

        ingestor = self._ingestor(watchlist_manager, playbook_runner)
        ingestor._observe_iocs(self.PAYLOAD, "all-knowledge", "point-1", "test-source")

        _, context = playbook_runner.handle_trigger.call_args[0]
        assert context["iocs"] == [{"ioc_type": "ip", "ioc_value": "203.0.113.7"}]

    def test_no_trigger_when_no_match(self):
        watchlist_manager = MagicMock()
        watchlist_manager.check_iocs.return_value = []
        playbook_runner = MagicMock()
        playbook_runner.handle_trigger = AsyncMock(return_value=[])

        ingestor = self._ingestor(watchlist_manager, playbook_runner)
        ingestor._observe_iocs(self.PAYLOAD, "all-knowledge", "point-1", "test-source")

        playbook_runner.handle_trigger.assert_not_called()

    def test_no_playbook_runner_does_not_raise(self):
        """watchlist-only ingestors (no playbook_runner configured) must keep working."""
        watchlist_manager = MagicMock()
        watchlist_manager.check_iocs.return_value = [{"alert_id": "a1"}]
        ingestor = self._ingestor(watchlist_manager, playbook_runner=None)
        ingestor._observe_iocs(self.PAYLOAD, "all-knowledge", "point-1", "test-source")  # must not raise

    def test_playbook_trigger_failure_does_not_raise(self):
        """A broken playbook must not take down ingestion itself."""
        watchlist_manager = MagicMock()
        watchlist_manager.check_iocs.return_value = [{"alert_id": "a1"}]
        playbook_runner = MagicMock()
        playbook_runner.handle_trigger = AsyncMock(side_effect=RuntimeError("boom"))
        ingestor = self._ingestor(watchlist_manager, playbook_runner)
        ingestor._observe_iocs(self.PAYLOAD, "all-knowledge", "point-1", "test-source")  # must not raise

    def test_safe_from_a_threadpoolexecutor_worker(self):
        """Mirrors process_directory's real call path: _observe_iocs is invoked
        from inside a ThreadPoolExecutor worker, never the main/event-loop
        thread. asyncio.run() must not collide with anything there."""
        alerts = [{"alert_id": "a1", "ioc_type": "ip", "ioc_value": "203.0.113.7"}]
        watchlist_manager = MagicMock()
        watchlist_manager.check_iocs.return_value = alerts
        playbook_runner = MagicMock()
        playbook_runner.handle_trigger = AsyncMock(return_value=[])
        ingestor = self._ingestor(watchlist_manager, playbook_runner)

        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(
                ingestor._observe_iocs, self.PAYLOAD, "all-knowledge", "point-1", "test-source",
            )
            future.result(timeout=5)  # re-raises if the worker thread raised

        playbook_runner.handle_trigger.assert_called_once()

    def test_safe_from_a_plain_worker_thread(self):
        """Mirrors the feed-poller's call path (asyncio.to_thread): a plain
        background thread with no event loop of its own."""
        import threading

        alerts = [{"alert_id": "a1", "ioc_type": "ip", "ioc_value": "203.0.113.7"}]
        watchlist_manager = MagicMock()
        watchlist_manager.check_iocs.return_value = alerts
        playbook_runner = MagicMock()
        playbook_runner.handle_trigger = AsyncMock(return_value=[])
        ingestor = self._ingestor(watchlist_manager, playbook_runner)

        errors: list[BaseException] = []

        def run() -> None:
            try:
                ingestor._observe_iocs(self.PAYLOAD, "all-knowledge", "point-1", "test-source")
            except BaseException as exc:  # pragma: no cover - only on regression
                errors.append(exc)

        thread = threading.Thread(target=run)
        thread.start()
        thread.join(timeout=5)

        assert not errors
        playbook_runner.handle_trigger.assert_called_once()
