"""Tests for analytics, alert disposition/promote, triage, assets, and query."""

from __future__ import annotations

import tempfile
from datetime import datetime, timedelta
from urllib.parse import parse_qs, urlsplit

import pytest
from fastapi.testclient import TestClient

from black_onyx.threat.analytics import AnalyticsEngine
from black_onyx.threat.asset_manager import AssetManager
from black_onyx.threat.case_manager import CaseManager
from black_onyx.threat.query_executor import QueryExecutor
from black_onyx.threat.watchlist_manager import WatchlistManager


def _become_role(
    admin_client: TestClient,
    *,
    role: str,
    email: str,
    password: str = "another correct horse battery",
    display_name: str = "Role User",
) -> TestClient:
    invitation = admin_client.post(
        "/api/v1/admin/invitations",
        json={"email": email, "role": role, "send_email": False},
    )
    assert invitation.status_code == 200
    token = parse_qs(urlsplit(invitation.json()["invitation_url"]).query)["token"][0]
    admin_client.cookies.clear()
    registered = admin_client.post(
        "/api/v1/auth/register",
        json={"token": token, "display_name": display_name, "password": password},
    )
    assert registered.status_code == 200
    admin_client.headers["X-CSRF-Token"] = registered.json()["csrf_token"]
    assert registered.json()["user"]["role"] == role
    return admin_client


@pytest.fixture
def tmp_dir():
    with tempfile.TemporaryDirectory() as d:
        yield d


@pytest.fixture
def watchlist_mgr(tmp_dir):
    mgr = WatchlistManager(persist_dir=tmp_dir)
    yield mgr
    mgr.close()


@pytest.fixture
def case_mgr(tmp_dir):
    mgr = CaseManager(persist_dir=tmp_dir)
    yield mgr
    mgr.close()


@pytest.fixture
def asset_mgr(tmp_dir):
    mgr = AssetManager(persist_dir=tmp_dir)
    yield mgr
    mgr.close()


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("QDRANT_STORAGE__STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("QDRANT_SECURITY__EXTERNAL_URL", "http://testserver")
    monkeypatch.setenv("BLACK_ONYX_AUTH_SECRET", "test-secret-that-is-long-and-random")
    # Avoid lifespan poller/Qdrant construction when a local .env enables feeds.
    monkeypatch.setenv("QDRANT_FEEDS__ENABLED", "false")
    monkeypatch.setenv("QDRANT_CONNECTORS__ENABLED", "false")
    from black_onyx.config import get_settings
    from black_onyx.auth.context import get_auth_service
    from black_onyx.api.service import AppService
    if AppService._instance is not None:
        AppService._instance._settings_store.database.close()
    AppService._instance = None
    AppService._initialized = False
    get_settings.cache_clear()
    get_auth_service.cache_clear()
    auth = get_auth_service()
    auth.bootstrap_admin("admin@example.com", "correct horse battery staple", "Admin")
    from black_onyx.api.app import create_app
    from unittest.mock import MagicMock

    # ensure_default_collections may still probe Qdrant; keep it from failing the suite
    monkeypatch.setattr(
        AppService, "ensure_default_collections", lambda self: [], raising=False,
    )
    monkeypatch.setattr(
        AppService, "start_background_schedulers", lambda self: None, raising=False,
    )

    class _FakeConnectorManager:
        def __init__(self):
            self._push_token = "test-push-token-value-xxxxxxxx"
            self._push_prefix = self._push_token[:8]

        def list_connectors(self):
            return []

        def list_recent_detections(self, qdrant_store, limit=20):
            return []

        async def push_detections(self, connector_id, detections):
            return {
                "connector": "fake",
                "mode": "push",
                "processed": len(detections),
                "skipped": 0,
                "errors": 0,
                "raw_count": len(detections),
            }

        def get_connector(self, connector_id):
            return {
                "id": connector_id,
                "name": "fake",
                "enabled": True,
                "collection": "detect-fake",
                "connector_type": "generic_rest",
                "base_url": "https://example.test",
                "poll_interval_minutes": 60,
                "config": {},
                "credential_env": {},
                "created_at": "2026-01-01T00:00:00+00:00",
                "updated_at": "2026-01-01T00:00:00+00:00",
                "push_token_prefix": self._push_prefix,
                "has_push_token": True,
            }

        def rotate_push_token(self, connector_id):
            row = self.get_connector(connector_id)
            return {**row, "push_token": self._push_token, "token": self._push_token}

        def authenticate_push_token(self, connector_id, token):
            if token == self._push_token:
                return self.get_connector(connector_id)
            return None

        def close(self):
            return None

    _fake_connectors = _FakeConnectorManager()

    monkeypatch.setattr(
        AppService, "connector_manager", property(lambda self: _fake_connectors),
    )
    monkeypatch.setattr(
        AppService, "qdrant_store", property(lambda self: MagicMock()),
    )
    monkeypatch.setattr(
        AppService, "feed_manager", property(lambda self: None),
    )
    with TestClient(create_app(), raise_server_exceptions=False) as test_client:
        yield test_client
    get_auth_service.cache_clear()
    get_settings.cache_clear()
    if AppService._instance is not None:
        AppService._instance._settings_store.database.close()
    AppService._instance = None
    AppService._initialized = False


@pytest.fixture
def authenticated(client: TestClient):
    response = client.post(
        "/api/v1/auth/login",
        headers={"Origin": "http://testserver"},
        json={"email": "admin@example.com", "password": "correct horse battery staple"},
    )
    assert response.status_code == 200
    csrf = response.json()["csrf_token"]
    client.headers.update({"Origin": "http://testserver", "X-CSRF-Token": csrf})
    return client


class TestWatchlistDisposition:
    def test_acknowledge_sets_acknowledged_at(self, watchlist_mgr):
        list_id = watchlist_mgr.create_watchlist("Bad IPs")
        watchlist_mgr.add_items(list_id, [("ipv4", "1.2.3.4")])
        alerts = watchlist_mgr.check_iocs({"ipv4": ["1.2.3.4"]})
        alert_id = alerts[0]["alert_id"]
        watchlist_mgr.acknowledge_alert(alert_id)
        alert = watchlist_mgr.get_alert(alert_id)
        assert alert["acknowledged"] == 1
        assert alert["acknowledged_at"]

    def test_dispose_false_positive_feedback(self, watchlist_mgr):
        list_id = watchlist_mgr.create_watchlist("Bad IPs")
        watchlist_mgr.add_items(list_id, [("ipv4", "9.9.9.9")])
        item = watchlist_mgr.get_items(list_id)[0]
        alerts = watchlist_mgr.check_iocs({"ipv4": ["9.9.9.9"]})
        updated = watchlist_mgr.dispose_alert(
            alerts[0]["alert_id"],
            "false_positive",
            disposition_by="analyst1",
            suppress_item=True,
            lower_confidence=True,
        )
        assert updated["disposition"] == "false_positive"
        assert updated["acknowledged_at"]
        item_after = watchlist_mgr.get_item(item["item_id"])
        assert item_after["suppressed"] == 1
        assert item_after["confidence"] < 1.0
        # Suppressed items no longer fire
        assert watchlist_mgr.check_iocs({"ipv4": ["9.9.9.9"]}) == []


class TestCaseTiming:
    def test_create_case_has_severity_and_sla(self, case_mgr):
        case = case_mgr.create_case(title="Timed", priority="critical")
        assert case.severity == "critical"
        assert case.detected_at
        assert case.sla_due_at
        fetched = case_mgr.get_case(case.case_id)
        assert fetched.severity == "critical"
        assert fetched.sla_due_at

    def test_close_stamps_closed_at(self, case_mgr):
        case = case_mgr.create_case(title="Close me")
        updated = case_mgr.update_case(case.case_id, status="closed")
        assert updated.closed_at


class TestAnalyticsEngine:
    def test_overview_and_kpis(self, watchlist_mgr, case_mgr):
        list_id = watchlist_mgr.create_watchlist("Ops")
        watchlist_mgr.add_items(list_id, [("ipv4", "8.8.8.8")])
        alerts = watchlist_mgr.check_iocs({"ipv4": ["8.8.8.8"]})
        past = (datetime.now() - timedelta(minutes=30)).isoformat()
        # Backdate triggered_at for MTTA
        watchlist_mgr._conn.execute(
            "UPDATE alerts SET triggered_at = ? WHERE alert_id = ?",
            (past, alerts[0]["alert_id"]),
        )
        watchlist_mgr._conn.commit()
        watchlist_mgr.dispose_alert(alerts[0]["alert_id"], "true_positive", disposition_by="a")
        case_mgr.create_case(title="C1", priority="high")

        engine = AnalyticsEngine(
            watchlist_manager=watchlist_mgr,
            case_manager=case_mgr,
        )
        overview = engine.overview("7d")
        assert overview["alerts"]["n"] >= 1
        assert "n" in overview
        assert "mtta" in overview["kpis"]

        kpis = engine.kpis(["mtta", "mttr", "fpr", "alert_volume"], "7d")
        assert kpis["metrics"]["mtta"]["n"] >= 1
        assert kpis["metrics"]["mtta"]["seconds"] is not None
        assert kpis["metrics"]["fpr"]["n"] >= 1
        assert kpis["metrics"]["alert_volume"]["count"] >= 1
        assert kpis["n"] >= 1

        coverage = engine.attack_coverage("30d")
        assert coverage["coverage_index"] < 1.0
        assert "risk_weighted_sightings" in coverage["coverage_basis"]
        assert "navigator" in coverage
        assert "techniques" in coverage["navigator"]

        mtta_ts = engine.timeseries("mtta", "day", "7d")
        assert "points" in mtta_ts
        assert mtta_ts["unit"] == "seconds"
        assert mtta_ts["n"] >= 1

        fpr_ts = engine.timeseries("fpr", "day", "7d")
        assert fpr_ts["unit"] == "ratio"

    def test_fpr_uses_tp_fp_denominator(self, watchlist_mgr, case_mgr):
        """FPR must be FP/(TP+FP); informational/other dispositions must not dilute it."""
        list_id = watchlist_mgr.create_watchlist("FPR mix")
        watchlist_mgr.add_items(list_id, [
            ("ipv4", "1.1.1.1"),
            ("ipv4", "2.2.2.2"),
            ("ipv4", "3.3.3.3"),
        ])
        alerts = watchlist_mgr.check_iocs({"ipv4": ["1.1.1.1", "2.2.2.2", "3.3.3.3"]})
        assert len(alerts) >= 3
        watchlist_mgr.dispose_alert(alerts[0]["alert_id"], "true_positive", disposition_by="a")
        watchlist_mgr.dispose_alert(alerts[1]["alert_id"], "false_positive", disposition_by="a")
        watchlist_mgr.dispose_alert(alerts[2]["alert_id"], "informational", disposition_by="a")
        engine = AnalyticsEngine(watchlist_manager=watchlist_mgr, case_manager=case_mgr)
        fpr = engine.kpis(["fpr"], "7d")["metrics"]["fpr"]
        assert fpr["n"] == 2
        assert fpr["false_positives"] == 1
        assert fpr["true_positives"] == 1
        assert abs(float(fpr["rate"]) - 0.5) < 1e-9

    def test_overview_asset_count(self, watchlist_mgr, case_mgr, asset_mgr):
        asset_mgr.create_asset(hostname="a1", criticality="high")
        asset_mgr.create_asset(hostname="a2", criticality="low")
        engine = AnalyticsEngine(
            watchlist_manager=watchlist_mgr,
            case_manager=case_mgr,
            asset_manager=asset_mgr,
        )
        overview = engine.overview("7d")
        assert overview["asset_count"] == 2
        assert overview["assets_by_criticality"]["high"] == 1
        dist = engine.distributions("asset_criticality", "30d")
        assert dist["n"] == 2


class TestAssets:
    def test_crud_and_csv(self, asset_mgr):
        asset = asset_mgr.create_asset(hostname="host1", ip_address="10.0.0.1")
        assert asset["asset_id"]
        listed = asset_mgr.list_assets()
        assert len(listed) == 1
        asset_mgr.update_asset(asset["asset_id"], criticality="high")
        assert asset_mgr.get_asset(asset["asset_id"])["criticality"] == "high"
        result = asset_mgr.import_csv(
            "hostname,ip_address,criticality\nhost2,10.0.0.2,low\n"
        )
        assert result["created"] == 1
        finding = asset_mgr.create_finding(
            title="Open RDP", asset_id=asset["asset_id"], severity="high",
        )
        board = asset_mgr.posture_board()
        assert board["n"] >= 1
        assert finding["finding_id"] in {f["finding_id"] for f in board["open_findings"]}
        asset_mgr.delete_asset(asset["asset_id"])
        assert asset_mgr.get_asset(asset["asset_id"]) is None


class TestQueryExecutor:
    def test_where_eq_and_limit(self, watchlist_mgr, case_mgr, asset_mgr):
        list_id = watchlist_mgr.create_watchlist("Q")
        watchlist_mgr.add_items(list_id, [("domain", "evil.test")])
        watchlist_mgr.check_iocs({"domains": ["evil.test"]})
        case_mgr.create_case(title="QueryCase")
        asset_mgr.create_asset(hostname="query-host")

        executor = QueryExecutor(
            alerts_loader=lambda: watchlist_mgr.get_alerts(limit=100),
            cases_loader=lambda: [c.__dict__ for c in case_mgr.list_cases()],
            assets_loader=lambda: asset_mgr.all_assets_raw(),
            detections_loader=lambda: [],
        )
        result = executor.execute(
            'alerts | where ioc_value == "evil.test" | project ioc_value, ioc_type | limit 10'
        )
        assert result["n"] == 1
        assert result["rows"][0]["ioc_value"] == "evil.test"

        cases = executor.execute("cases | where title contains Query | limit 5")
        assert cases["n"] == 1

        sorted_cases = executor.execute("cases | sort title desc | limit 5")
        assert sorted_cases["n"] >= 1

        summarized = executor.execute("cases | summarize count() by priority")
        assert summarized["n"] >= 1
        assert "count" in summarized["rows"][0]

        in_filter = executor.execute(
            'alerts | where ioc_value in ("evil.test", "other.test") | limit 10'
        )
        assert in_filter["n"] == 1

        neq = executor.execute('cases | where status != "closed" | limit 10')
        assert neq["n"] >= 1

        evidence_exec = QueryExecutor(
            alerts_loader=lambda: [],
            cases_loader=lambda: [],
            assets_loader=lambda: [],
            detections_loader=lambda: [],
            evidence_loader=lambda: [
                {
                    "collection": "all-knowledge",
                    "point_id": "1",
                    "source_file": "a.txt",
                    "text": "powershell encoded command",
                    "indexed_at": "2026-08-01T00:00:00",
                }
            ],
        )
        evidence = evidence_exec.execute(
            'evidence | where text contains "powershell" | project collection, text | limit 5'
        )
        assert evidence["n"] == 1
        assert evidence["source"] == "evidence"


class TestAPIIntegration:
    def test_analytics_overview_kpis(self, authenticated: TestClient):
        overview = authenticated.get("/api/v1/analytics/overview?range=7d")
        assert overview.status_code == 200
        body = overview.json()
        assert "alerts" in body
        assert "kpis" in body
        assert "n" in body

        kpis = authenticated.get(
            "/api/v1/analytics/kpis?metrics=mtta,mtti,mttr,ingest_latency,fpr,intel_hit_rate,automation_success&range=7d"
        )
        assert kpis.status_code == 200
        metrics = kpis.json()["metrics"]
        assert "mtta" in metrics
        assert "mtti" in metrics
        assert "ingest_latency" in metrics
        assert "intel_hit_rate" in metrics
        assert "automation_success" in metrics

        playbooks = authenticated.get("/api/v1/analytics/playbooks?range=30d")
        assert playbooks.status_code == 200
        assert "n" in playbooks.json()
        assert "success_rate" in playbooks.json()
        assert "playbook_success_rate" in overview.json() or overview.json().get("playbooks") is not None

        cti = authenticated.get("/api/v1/analytics/cti/impact?range=30d")
        assert cti.status_code == 200
        assert "geo" in cti.json()
        assert "cves" in cti.json()
        assert "funnel" in cti.json()
        assert "ioc_freshness" in cti.json()

        for metric in (
            "noisy_ioc", "enrichment_verdict", "assignee", "sla_aging",
            "webhook_volume", "dedup_savings",
        ):
            dist = authenticated.get(f"/api/v1/analytics/distributions?metric={metric}&range=30d")
            assert dist.status_code == 200, metric
            assert "points" in dist.json() or "items" in dist.json() or "n" in dist.json()

        webhook_ts = authenticated.get("/api/v1/analytics/timeseries?metric=webhooks&group_by=day&range=7d")
        assert webhook_ts.status_code == 200

    def test_disposition_ack_and_promote(self, authenticated: TestClient):
        wl = authenticated.post(
            "/api/v1/watchlists",
            json={"name": "Promo", "description": ""},
        )
        assert wl.status_code == 200
        list_id = wl.json()["list_id"]
        authenticated.post(
            f"/api/v1/watchlists/{list_id}/items",
            json={"items": [{"ioc_type": "ipv4", "ioc_value": "203.0.113.10"}]},
        )
        from black_onyx.api.service import get_service
        alerts = get_service().watchlist_manager.check_iocs({"ipv4": ["203.0.113.10"]})
        alert_id = alerts[0]["alert_id"]

        disposed = authenticated.post(
            f"/api/v1/alerts/{alert_id}/disposition",
            json={"disposition": "informational", "note": "noise"},
        )
        assert disposed.status_code == 200
        assert disposed.json()["alert"]["disposition"] == "informational"
        assert disposed.json()["alert"]["acknowledged_at"]

        # Fresh alert for promote
        alerts2 = get_service().watchlist_manager.check_iocs({"ipv4": ["203.0.113.10"]})
        promote = authenticated.post(
            f"/api/v1/alerts/{alerts2[0]['alert_id']}/promote",
            json={"title": "Promoted case", "priority": "high"},
        )
        assert promote.status_code == 200
        assert promote.json()["case_id"]
        assert promote.json()["alert"]["promoted_case_id"] == promote.json()["case_id"]
        case = authenticated.get(f"/api/v1/cases/{promote.json()['case_id']}")
        assert case.status_code == 200
        assert case.json()["detected_at"]
        assert case.json()["sla_due_at"]

    def test_triage_and_assets_and_query(self, authenticated: TestClient, monkeypatch):
        from black_onyx.api import routes_assets

        registry: dict[str, dict] = {}

        async def upsert(payload, _user=None):
            registry[payload["asset_id"]] = routes_assets._normalize_registry_row(payload)
            return True

        async def fetch(asset_id, _user=None):
            return registry.get(asset_id)

        async def list_registry(_user=None):
            return list(registry.values())

        monkeypatch.setattr(routes_assets, "_upsert_registry_asset", upsert)
        monkeypatch.setattr(routes_assets, "_fetch_registry_asset", fetch)
        monkeypatch.setattr(routes_assets, "_list_registry_assets", list_registry)

        triage = authenticated.get("/api/v1/triage?limit=20")
        assert triage.status_code == 200
        assert "items" in triage.json()

        created = authenticated.post(
            "/api/v1/assets",
            json={"hostname": "api-host", "ip_address": "10.1.2.3", "criticality": "high"},
        )
        assert created.status_code == 200
        asset_id = created.json()["asset_id"]
        listed = authenticated.get("/api/v1/assets")
        assert listed.status_code == 200
        assert listed.json()["n"] >= 1

        wl = authenticated.post("/api/v1/watchlists", json={"name": "AssetHost", "description": ""})
        assert wl.status_code == 200
        authenticated.post(
            f"/api/v1/watchlists/{wl.json()['list_id']}/items",
            json={"items": [{"ioc_type": "hostname", "ioc_value": "api-host"}]},
        )
        from black_onyx.api.service import get_service
        get_service().watchlist_manager.check_iocs({"hostname": ["api-host"]})

        detail = authenticated.get(f"/api/v1/assets/{asset_id}")
        assert detail.status_code == 200
        assert "related_alerts" in detail.json()
        assert "related_detections" in detail.json()
        assert "related_iocs" in detail.json()
        assert any(a.get("ioc_value") == "api-host" for a in detail.json()["related_alerts"])

        case = authenticated.post("/api/v1/cases", json={"title": "Asset link"})
        assert case.status_code == 200
        link = authenticated.post(
            f"/api/v1/assets/{asset_id}/cases",
            json={"case_id": case.json()["case_id"]},
        )
        assert link.status_code == 200

        query = authenticated.post(
            "/api/v1/query",
            json={"query": "assets | where hostname == api-host | limit 5"},
        )
        assert query.status_code == 200
        assert query.json()["n"] >= 1

        evidence_q = authenticated.post(
            "/api/v1/query",
            json={"query": "evidence | limit 5"},
        )
        assert evidence_q.status_code == 200
        assert evidence_q.json()["source"] == "evidence"
        assert "rows" in evidence_q.json()

        webhooks_q = authenticated.post(
            "/api/v1/query",
            json={"query": "webhooks | limit 5"},
        )
        assert webhooks_q.status_code == 200
        assert webhooks_q.json()["source"] == "webhooks"

    def test_webhook_event_and_detection_disposition(self, authenticated: TestClient, tmp_path):
        from black_onyx.threat.webhook_manager import WebhookManager
        from black_onyx.connectors.connector_manager import DetectionConnectorManager
        from black_onyx.threat.asset_manager import AssetManager

        wh = WebhookManager(persist_dir=str(tmp_path / "wh"))
        created = wh.create_webhook("triage-hook")
        event = wh.record_event(
            webhook_id=created["webhook_id"],
            webhook_name="triage-hook",
            source="webhook:triage-hook",
            iocs={"domains": ["evil.test"]},
            alert_ids=[],
        )
        disposed = wh.dispose_event(event["event_id"], disposition="informational", disposition_by="analyst")
        assert disposed["disposition"] == "informational"
        assert disposed["acknowledged"] is True

        assets = AssetManager(persist_dir=str(tmp_path / "assets"))
        mgr = DetectionConnectorManager(persist_dir=str(tmp_path / "conn"), asset_manager=assets)
        mgr._conn.execute(
            "INSERT INTO seen_detections (connector_id, detection_key, first_seen_at) VALUES (?, ?, ?)",
            ("demo", "connector:demo:abc", "2026-01-01T00:00:00+00:00"),
        )
        mgr._conn.commit()
        det = mgr.dispose_detection(
            "connector:demo:abc",
            disposition="true_positive",
            disposition_by="analyst",
            connector="demo",
            title="Demo detection",
        )
        assert det["disposition"] == "true_positive"
        with pytest.raises(LookupError):
            mgr.dispose_detection("never-seen-key", disposition="informational")
        asset = assets.upsert_from_sighting(
            hostname="host-a.example",
            ip_address="10.9.8.7",
            username="alice",
            source="connector:demo",
        )
        assert asset
        assert asset["hostname"] == "host-a.example"
        again = assets.upsert_from_sighting(hostname="host-a.example", source="connector:demo")
        assert again["asset_id"] == asset["asset_id"]

    def test_detection_rules_validate_and_create(self, authenticated: TestClient):
        sigma = """
title: Test Rule
id: 11111111-1111-1111-1111-111111111111
logsource:
  product: windows
detection:
  selection:
    Image|endswith: '\\cmd.exe'
  condition: selection
level: medium
"""
        validated = authenticated.post(
            "/api/v1/detection-rules/validate",
            json={"rule_type": "sigma", "content": sigma},
        )
        assert validated.status_code == 200
        assert validated.json()["ok"] is True

        created = authenticated.post(
            "/api/v1/detection-rules",
            json={"name": "Test Sigma", "rule_type": "sigma", "content": sigma},
        )
        assert created.status_code == 200
        rule_id = created.json()["rule_id"]
        assert rule_id
        listed = authenticated.get("/api/v1/detection-rules")
        assert listed.status_code == 200
        assert listed.json()["n"] >= 1

        submitted = authenticated.patch(
            f"/api/v1/detection-rules/{rule_id}",
            json={"status": "pending_approval"},
        )
        assert submitted.status_code == 200
        assert submitted.json()["status"] == "pending_approval"
        assert submitted.json()["submitted_at"]

        approved = authenticated.patch(
            f"/api/v1/detection-rules/{rule_id}",
            json={"status": "approved"},
        )
        assert approved.status_code == 200
        assert approved.json()["status"] == "approved"
        assert approved.json()["approved_at"]
        assert approved.json()["approved_by"]

    def test_connector_push_endpoint(self, authenticated: TestClient):
        pushed = authenticated.post(
            "/api/v1/connectors/conn-fake/push",
            json={"detections": [{"id": "1", "summary": "pushed"}]},
        )
        assert pushed.status_code == 200, pushed.text
        body = pushed.json()
        assert body["mode"] == "push"
        assert body["processed"] == 1

        rotated = authenticated.post("/api/v1/connectors/conn-fake/push-token")
        assert rotated.status_code == 200, rotated.text
        token = rotated.json()["token"]
        assert token

        # Token ingest skips CSRF; header is validated in the route.
        token_push = authenticated.post(
            "/api/v1/connectors/conn-fake/push",
            headers={"X-Connector-Token": token},
            json={"detections": [{"id": "2", "summary": "token-pushed"}]},
        )
        assert token_push.status_code == 200, token_push.text
        assert token_push.json()["processed"] == 1

        rejected = authenticated.post(
            "/api/v1/connectors/conn-fake/push",
            headers={"X-Connector-Token": "wrong-token"},
            json={"detections": [{"id": "3"}]},
        )
        assert rejected.status_code == 401

        # Session push without CSRF must fail; token header alone may skip CSRF.
        csrf = authenticated.headers.pop("X-CSRF-Token", None)
        forged = authenticated.post(
            "/api/v1/connectors/conn-fake/push",
            json={"detections": [{"id": "csrf-probe"}]},
        )
        assert forged.status_code == 403
        token_only = authenticated.post(
            "/api/v1/connectors/conn-fake/push",
            headers={"X-Connector-Token": token},
            json={"detections": [{"id": "4", "summary": "token-no-csrf"}]},
        )
        assert token_only.status_code == 200, token_only.text
        if csrf:
            authenticated.headers["X-CSRF-Token"] = csrf

    def test_analytics_views_and_time_in_status(self, authenticated: TestClient):
        created = authenticated.post(
            "/api/v1/analytics/views",
            json={"name": "Ops home", "range": "7d", "tab": "response", "role_default": "admin"},
        )
        assert created.status_code == 200, created.text
        assert created.json()["name"] == "Ops home"
        listed = authenticated.get("/api/v1/analytics/views")
        assert listed.status_code == 200
        assert listed.json()["n"] >= 1
        view_id = created.json()["view_id"]

        case = authenticated.post("/api/v1/cases", json={"title": "Dwell case", "priority": "high"})
        assert case.status_code == 200
        case_id = case.json()["case_id"]
        patched = authenticated.patch(f"/api/v1/cases/{case_id}", json={"status": "investigating"})
        assert patched.status_code == 200
        detail = authenticated.get(f"/api/v1/cases/{case_id}")
        assert detail.status_code == 200
        events = detail.json().get("timeline") or []
        assert any(e.get("event_type") == "status_change" for e in events)

        dwell = authenticated.get("/api/v1/analytics/distributions?metric=time_in_status&range=30d")
        assert dwell.status_code == 200
        assert "items" in dwell.json()

        for metric in (
            "intel_age_at_match", "enrichment_coverage", "detections_by_connector",
        ):
            dist = authenticated.get(f"/api/v1/analytics/distributions?metric={metric}&range=30d")
            assert dist.status_code == 200, metric
            assert "items" in dist.json() or "n" in dist.json()

        reopen = authenticated.get("/api/v1/analytics/kpis?metrics=reopen_rate&range=30d")
        assert reopen.status_code == 200
        assert "reopen_rate" in reopen.json()["metrics"]

        for metric in ("fresh_iocs", "stale_iocs"):
            ts = authenticated.get(f"/api/v1/analytics/timeseries?metric={metric}&group_by=day&range=30d")
            assert ts.status_code == 200, metric

        deleted = authenticated.delete(f"/api/v1/analytics/views/{view_id}")
        assert deleted.status_code == 200

    def test_report_template_persisted(self, authenticated: TestClient):
        generated = authenticated.post(
            "/api/v1/reports/generate",
            json={
                "title": "Ops digest template test",
                "format": "markdown",
                "template": "ops_digest",
                "body_markdown": "# Digest\n\n- MTTA: 1m",
                "iocs": {},
            },
        )
        assert generated.status_code == 200, generated.text
        listed = authenticated.get("/api/v1/reports?template=ops_digest")
        assert listed.status_code == 200
        rows = listed.json()["reports"]
        assert any(r.get("title") == "Ops digest template test" for r in rows)
        assert any(r.get("template") == "ops_digest" for r in rows)

    def test_role_matrix_analytics_and_query(self, authenticated: TestClient):
        overview = authenticated.get("/api/v1/analytics/overview?range=7d")
        assert overview.status_code == 200

        analyst = _become_role(
            authenticated,
            role="analyst",
            email="analyst-ops@example.com",
            display_name="Analyst Ops",
        )
        assert analyst.get("/api/v1/analytics/overview?range=7d").status_code == 200
        assert analyst.get("/api/v1/triage?limit=10").status_code == 200
        assert analyst.post(
            "/api/v1/query",
            json={"query": "webhooks | limit 5"},
        ).status_code == 200
        # Analysts cannot publish org role-default views.
        denied_default = analyst.post(
            "/api/v1/analytics/views",
            json={"name": "Analyst hijack", "range": "7d", "tab": "volume", "role_default": "analyst"},
        )
        assert denied_default.status_code == 403
        personal = analyst.post(
            "/api/v1/analytics/views",
            json={"name": "Analyst personal", "range": "7d", "tab": "volume"},
        )
        assert personal.status_code == 200

        # Re-login as admin to invite a viewer (analyst session currently).
        admin_login = analyst.post(
            "/api/v1/auth/login",
            headers={"Origin": "http://testserver"},
            json={"email": "admin@example.com", "password": "correct horse battery staple"},
        )
        assert admin_login.status_code == 200
        analyst.headers["X-CSRF-Token"] = admin_login.json()["csrf_token"]

        viewer = _become_role(
            analyst,
            role="viewer",
            email="viewer-ops@example.com",
            display_name="Viewer Ops",
        )
        assert viewer.get("/api/v1/analytics/overview?range=7d").status_code == 200
        assert viewer.get("/api/v1/triage?limit=10").status_code == 200
        assert viewer.post(
            "/api/v1/query",
            json={"query": "webhooks | limit 5"},
        ).status_code == 403
        assert viewer.post(
            "/api/v1/analytics/views",
            json={"name": "viewer-view", "range": "7d", "tab": "volume"},
        ).status_code == 403

    def test_evidence_query_requires_bound(self, authenticated: TestClient):
        unbounded = authenticated.post(
            "/api/v1/query",
            json={"query": "evidence"},
        )
        assert unbounded.status_code == 422
        bounded = authenticated.post(
            "/api/v1/query",
            json={"query": "evidence | limit 5"},
        )
        assert bounded.status_code == 200
