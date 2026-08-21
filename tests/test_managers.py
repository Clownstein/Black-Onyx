"""Tests for case management, watchlists, annotations, and decay tracking."""

import pytest
import tempfile

from black_onyx.threat.case_manager import CaseManager
from black_onyx.threat.watchlist_manager import WatchlistManager
from black_onyx.threat.annotation_manager import AnnotationManager
from black_onyx.threat.decay_manager import DecayManager


@pytest.fixture
def tmp_dir():
    with tempfile.TemporaryDirectory() as d:
        yield d


@pytest.fixture
def case_mgr(tmp_dir):
    mgr = CaseManager(persist_dir=tmp_dir)
    yield mgr
    mgr.close()


@pytest.fixture
def watchlist_mgr(tmp_dir):
    mgr = WatchlistManager(persist_dir=tmp_dir)
    yield mgr
    mgr.close()


@pytest.fixture
def annotation_mgr(tmp_dir):
    mgr = AnnotationManager(persist_dir=tmp_dir)
    yield mgr
    mgr.close()


@pytest.fixture
def decay_mgr(tmp_dir):
    mgr = DecayManager(persist_dir=tmp_dir)
    yield mgr
    mgr.close()


class TestCaseManager:
    def test_create_and_get(self, case_mgr):
        case = case_mgr.create_case(title="Test Case", description="Testing", priority="high")
        assert case.case_id
        assert case.title == "Test Case"
        fetched = case_mgr.get_case(case.case_id)
        assert fetched is not None
        assert fetched.title == "Test Case"

    def test_list_cases(self, case_mgr):
        case_mgr.create_case(title="Case 1")
        case_mgr.create_case(title="Case 2")
        cases = case_mgr.list_cases()
        assert len(cases) == 2

    def test_update_case(self, case_mgr):
        case = case_mgr.create_case(title="Original")
        updated = case_mgr.update_case(case.case_id, status="closed", priority="low")
        assert updated.status == "closed"
        assert updated.priority == "low"

    def test_add_ioc_and_note(self, case_mgr):
        case = case_mgr.create_case(title="IOC Case")
        case_mgr.add_ioc_to_case(case.case_id, "ipv4", "1.2.3.4")
        case_mgr.add_note(case.case_id, "analyst", "Suspicious IP found")
        iocs = case_mgr.get_case_iocs(case.case_id)
        notes = case_mgr.get_notes(case.case_id)
        assert len(iocs) == 1
        assert iocs[0]["ioc_value"] == "1.2.3.4"
        assert len(notes) == 1
        assert notes[0]["content"] == "Suspicious IP found"

    def test_timeline(self, case_mgr):
        case = case_mgr.create_case(title="Timeline Test")
        case_mgr.add_timeline_event(case.case_id, "ioc_found", "Discovered malicious IP")
        timeline = case_mgr.get_timeline(case.case_id)
        assert sorted(event["event_type"] for event in timeline) == ["ioc_found", "status_change"]

    def test_delete_case(self, case_mgr):
        case = case_mgr.create_case(title="To Delete")
        case_mgr.delete_case(case.case_id)
        assert case_mgr.get_case(case.case_id) is None


class TestWatchlistManager:
    def test_create_and_list(self, watchlist_mgr):
        watchlist_mgr.create_watchlist("Bad IPs", "Known malicious IPs")
        lists = watchlist_mgr.list_watchlists()
        assert len(lists) == 1
        assert lists[0]["name"] == "Bad IPs"

    def test_add_items(self, watchlist_mgr):
        list_id = watchlist_mgr.create_watchlist("Bad IPs")
        watchlist_mgr.add_items(list_id, [("ipv4", "1.2.3.4"), ("ipv4", "5.6.7.8")])
        items = watchlist_mgr.get_items(list_id)
        assert len(items) == 2

    def test_check_iocs_match(self, watchlist_mgr):
        list_id = watchlist_mgr.create_watchlist("Bad IPs")
        watchlist_mgr.add_items(list_id, [("ipv4", "1.2.3.4")])
        alerts = watchlist_mgr.check_iocs({"ipv4": ["1.2.3.4", "10.0.0.1"]})
        assert len(alerts) == 1
        assert alerts[0]["ioc_value"] == "1.2.3.4"

    def test_check_iocs_no_match(self, watchlist_mgr):
        list_id = watchlist_mgr.create_watchlist("Bad IPs")
        watchlist_mgr.add_items(list_id, [("ipv4", "1.2.3.4")])
        alerts = watchlist_mgr.check_iocs({"ipv4": ["10.0.0.1"]})
        assert len(alerts) == 0

    def test_get_alerts_includes_watchlist_name_and_ioc(self, watchlist_mgr):
        """get_alerts() previously did a bare `SELECT * FROM alerts`, which
        has no ioc_type/ioc_value/watchlist_name columns at all — those only
        existed transiently in check_iocs()'s own return value. Any caller
        (the /api/v1/alerts route, the Watchlists and Dashboard pages)
        rendering those fields from a *later* GET was silently showing
        nothing. This asserts the join actually supplies them."""
        list_id = watchlist_mgr.create_watchlist("Bad IPs")
        watchlist_mgr.add_items(list_id, [("ipv4", "1.2.3.4")])
        watchlist_mgr.check_iocs({"ipv4": ["1.2.3.4"]}, collection="all-knowledge", point_id="p1")
        alerts = watchlist_mgr.get_alerts()
        assert len(alerts) == 1
        assert alerts[0]["ioc_type"] == "ipv4"
        assert alerts[0]["ioc_value"] == "1.2.3.4"
        assert alerts[0]["watchlist_name"] == "Bad IPs"
        assert alerts[0]["collection"] == "all-knowledge"

    def test_acknowledge_alert(self, watchlist_mgr):
        list_id = watchlist_mgr.create_watchlist("Bad IPs")
        watchlist_mgr.add_items(list_id, [("ipv4", "1.2.3.4")])
        alerts = watchlist_mgr.check_iocs({"ipv4": ["1.2.3.4"]})
        alert_id = alerts[0]["alert_id"]
        watchlist_mgr.acknowledge_alert(alert_id)
        unack = watchlist_mgr.get_alerts(unacknowledged_only=True)
        assert len(unack) == 0

    def test_delete_watchlist(self, watchlist_mgr):
        list_id = watchlist_mgr.create_watchlist("To Delete")
        watchlist_mgr.delete_watchlist(list_id)
        lists = watchlist_mgr.list_watchlists()
        assert len(lists) == 0


class TestAnnotationManager:
    def test_add_and_get_annotation(self, annotation_mgr):
        annotation_mgr.add_annotation("col", "point1", "analyst1", "Suspicious")
        anns = annotation_mgr.get_annotations("col", "point1")
        assert len(anns) == 1
        assert anns[0]["content"] == "Suspicious"

    def test_tags(self, annotation_mgr):
        annotation_mgr.add_tag("col", "point1", "malicious")
        annotation_mgr.add_tag("col", "point1", "confirmed")
        tags = annotation_mgr.get_tags("col", "point1")
        assert "malicious" in tags
        assert "confirmed" in tags
        annotation_mgr.remove_tag("col", "point1", "malicious")
        tags = annotation_mgr.get_tags("col", "point1")
        assert "malicious" not in tags
        assert "confirmed" in tags

    def test_notes(self, annotation_mgr):
        annotation_mgr.add_note("col", "point1", "analyst", "Investigating")
        notes = annotation_mgr.get_notes("col", "point1")
        assert len(notes) == 1
        assert notes[0]["content"] == "Investigating"

    def test_bookmark_toggle(self, annotation_mgr):
        assert annotation_mgr.toggle_bookmark("col", "point1", "user1")
        assert annotation_mgr.is_bookmarked("col", "point1", "user1")
        assert not annotation_mgr.toggle_bookmark("col", "point1", "user1")
        assert not annotation_mgr.is_bookmarked("col", "point1", "user1")

    def test_confidence(self, annotation_mgr):
        annotation_mgr.set_confidence("col", "point1", 0.85)
        assert annotation_mgr.get_confidence("col", "point1") == 0.85

    def test_status(self, annotation_mgr):
        annotation_mgr.set_status("col", "point1", "confirmed")
        assert annotation_mgr.get_status("col", "point1") == "confirmed"


class TestDecayManager:
    def test_record_sighting(self, decay_mgr):
        decay_mgr.record_sighting("ipv4", "1.2.3.4", "feed1")
        tracked = decay_mgr.get_all_tracked()
        assert len(tracked) == 1
        assert tracked[0]["ioc_value"] == "1.2.3.4"

    def test_multiple_sightings(self, decay_mgr):
        decay_mgr.record_sighting("ipv4", "1.2.3.4", "feed1")
        decay_mgr.record_sighting("ipv4", "1.2.3.4", "feed2")
        history = decay_mgr.get_ioc_history("1.2.3.4")
        assert history["sighting_count"] == 2
        assert len(history["sources"]) == 2

    def test_decay_score_fresh(self, decay_mgr):
        # Record 10 sightings so sighting_factor = 1.0
        for i in range(10):
            decay_mgr.record_sighting("ipv4", "1.2.3.4")
        score = decay_mgr.calculate_decay_score("1.2.3.4")
        # Fresh IOC with many sightings should have high score
        assert score > 0.9

    def test_decay_score_low_sightings(self, decay_mgr):
        decay_mgr.record_sighting("ipv4", "1.2.3.4")
        score = decay_mgr.calculate_decay_score("1.2.3.4")
        # 1 sighting = 0.1 sighting_factor
        assert 0.0 < score <= 0.2

    def test_stale_and_fresh(self, decay_mgr):
        for i in range(10):
            decay_mgr.record_sighting("ipv4", "1.2.3.4")
        decay_mgr.update_all_scores()
        fresh = decay_mgr.get_fresh_iocs(threshold_score=0.5)
        stale = decay_mgr.get_stale_iocs(threshold_score=0.5)
        assert len(fresh) == 1
        assert len(stale) == 0

    def test_update_all_scores(self, decay_mgr):
        decay_mgr.record_sighting("ipv4", "1.2.3.4")
        decay_mgr.record_sighting("domain", "evil.com")
        count = decay_mgr.update_all_scores()
        assert count == 2

    def test_record_batch(self, decay_mgr):
        iocs = {"ipv4": ["1.2.3.4", "5.6.7.8"], "domain": ["evil.com"]}
        decay_mgr.record_sightings_batch(iocs, source="test")
        tracked = decay_mgr.get_all_tracked()
        assert len(tracked) == 3
