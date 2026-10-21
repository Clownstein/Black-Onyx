"""Wazuh connector, private push URL policy, and the Wazuh/Suricata shipper."""

from __future__ import annotations

import asyncio
import importlib.util
import json
import os
import re
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from black_onyx.connectors.connector_manager import DetectionConnectorManager
from black_onyx.connectors.factory import create_detection_connector
from black_onyx.connectors.wazuh import WazuhConnector, wazuh_severity
from black_onyx.pipeline.ingestor import Ingestor

ROOT = Path(__file__).resolve().parents[1]
SHIPPER_PATH = ROOT / "detection" / "collectors" / "shipper" / "black_onyx_shipper.py"
ULID_RE = re.compile(r"^[0-7][0-9A-HJKMNP-TV-Z]{25}$")


def _load_shipper():
    spec = importlib.util.spec_from_file_location("black_onyx_shipper", SHIPPER_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["black_onyx_shipper"] = module
    spec.loader.exec_module(module)
    return module


shipper = _load_shipper()


def _now_ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000+0000")


def _syscheck_alert() -> dict:
    return {
        "id": "1714567890.12345",
        "timestamp": _now_ts(),
        "rule": {
            "id": "550", "level": 10, "description": "Integrity checksum changed.",
            "groups": ["ossec", "syscheck", "syscheck_entry_modified"],
            "mitre": {"id": ["T1565.001"], "tactic": ["Impact"], "technique": ["Stored Data Manipulation"]},
        },
        "agent": {"id": "003", "name": "web-01", "ip": "10.0.0.15"},
        "syscheck": {
            "path": "/etc/passwd", "event": "modified", "uname_after": "root",
            "sha256_after": "A" * 64, "md5_after": "B" * 32, "sha1_after": "C" * 40,
        },
        "data": {"srcip": "203.0.113.50"},
        "full_log": "File '/etc/passwd' modified",
    }


def _sysmon_alert(eid: int, eventdata: dict, *, level: int = 3) -> dict:
    return {
        "id": f"1714567890.{eid}",
        "timestamp": _now_ts(),
        "rule": {"id": "61603", "level": level, "description": "Sysmon event", "groups": ["windows", "sysmon"]},
        "agent": {"id": "007", "name": "ws-07", "ip": "10.0.0.77"},
        "data": {"win": {
            "system": {"eventID": str(eid), "providerName": "Microsoft-Windows-Sysmon"},
            "eventdata": eventdata,
        }},
    }


def _suricata_eve(signature_id: int = 2027865) -> dict:
    return {
        "timestamp": _now_ts(),
        "event_type": "alert",
        "src_ip": "10.0.0.15", "src_port": 51515, "dest_ip": "198.51.100.7", "dest_port": 443, "proto": "TCP",
        "community_id": "1:abc=",
        "alert": {
            "signature_id": signature_id, "signature": "ET MALWARE Test C2", "severity": 1,
            "metadata": {"mitre_technique_id": ["T1071"], "mitre_tactic_id": ["TA0011"]},
        },
    }


@pytest.fixture
def tmp_dir():
    with tempfile.TemporaryDirectory() as d:
        yield d


def _public_dns():
    return patch(
        "black_onyx.net.safe_url.socket.getaddrinfo",
        return_value=[(2, 1, 6, "", ("93.184.216.34", 443))],
    )


def _private_dns():
    return patch(
        "black_onyx.net.safe_url.socket.getaddrinfo",
        return_value=[(2, 1, 6, "", ("10.20.30.40", 443))],
    )


# ----------------------------------------------------------------- connector


class TestWazuhConnector:
    def test_factory_dispatches_wazuh_without_public_url(self):
        connector = create_detection_connector("wazuh", "wz", {"base_url": "https://wazuh.corp.local"}, {})
        assert isinstance(connector, WazuhConnector)
        assert connector.source_type == "wazuh"

    def test_normalize_maps_rule_agent_syscheck_and_mitre(self):
        connector = create_detection_connector("wazuh", "wz", {"base_url": "https://wazuh.corp.local"}, {})
        model = connector.normalize(_syscheck_alert())
        assert model.title == "Integrity checksum changed. on web-01"
        assert model.source_file == "connector:wz:003:550:1714567890.12345"
        assert model.ip_addresses[0] == "10.0.0.15"
        assert "203.0.113.50" in model.ip_addresses
        assert model.sha256_hashes == ["a" * 64]
        assert model.md5_hashes == ["b" * 32]
        assert model.sha1_hashes == ["c" * 40]
        assert model.mitre_techniques == ["T1565.001"]
        assert model.mitre_tactics == ["Impact"]
        assert model.ioc_tags[0] == "high"
        assert model.enrichment_data["hostname"] == "web-01"
        assert model.enrichment_data["username"] == "root"
        assert model.enrichment_data["asset_id"] == "wazuh:003"
        assert "/etc/passwd" in model.body_text

    def test_normalize_parses_sysmon_hashes(self):
        connector = create_detection_connector("wazuh", "wz", {"base_url": "https://wazuh.corp.local"}, {})
        model = connector.normalize(_sysmon_alert(1, {
            "image": "C:\\Windows\\System32\\cmd.exe", "commandLine": "cmd /c whoami",
            "hashes": "SHA256=" + "D" * 64 + ",MD5=" + "E" * 32,
        }))
        assert model.sha256_hashes == ["d" * 64]
        assert model.md5_hashes == ["e" * 32]
        assert "cmd /c whoami" in model.body_text

    def test_severity_bands(self):
        assert [wazuh_severity(v) for v in (3, 7, 10, 12, "x")] == ["low", "medium", "high", "critical", "low"]

    def test_push_only_poll_returns_nothing_and_test_reports_push_mode(self):
        connector = create_detection_connector("wazuh", "wz", {"base_url": "https://wazuh.corp.local"}, {})
        result = asyncio.run(connector.pull_detections(since=None, cursor=None))
        assert result.detections == []
        assert asyncio.run(connector.test_connection())["mode"] == "push"

    def test_poll_rejects_private_indexer(self):
        connector = create_detection_connector(
            "wazuh", "wz", {"base_url": "https://wazuh.corp.local", "poll_enabled": True},
            {"username": "u", "password": "p"},
        )
        with _private_dns(), pytest.raises(ValueError, match="non-public"):
            asyncio.run(connector.pull_detections(since=None, cursor=None))

    def test_poll_pages_with_search_after(self):
        connector = create_detection_connector(
            "wazuh", "wz", {"base_url": "https://indexer.example.com", "poll_enabled": True, "min_level": 9},
            {"username": "u", "password": "p"},
        )
        pages = [
            ({"hits": {"hits": [{"_source": _syscheck_alert(), "sort": [1, "a"]}]}}, MagicMock()),
        ]
        calls: list[dict] = []

        async def fake_bounded(client, method, url, max_bytes, **kwargs):
            calls.append({"method": method, "url": url, **kwargs})
            return pages.pop(0) if pages else ({"hits": {"hits": []}}, MagicMock())

        with _public_dns(), patch("black_onyx.connectors.wazuh._bounded_json", side_effect=fake_bounded):
            result = asyncio.run(connector.pull_detections(since=datetime(2026, 1, 1, tzinfo=timezone.utc), cursor=None))
        assert len(result.detections) == 1
        assert json.loads(result.next_cursor) == [1, "a"]
        assert calls[0]["method"] == "POST"
        assert calls[0]["url"] == "https://indexer.example.com/wazuh-alerts-*/_search"
        filters = calls[0]["json"]["query"]["bool"]["filter"]
        assert {"range": {"rule.level": {"gte": 9}}} in filters
        assert any("timestamp" in f["range"] for f in filters)
        must_not = calls[0]["json"]["query"]["bool"]["must_not"]
        assert must_not == [{"terms": {"rule.groups": ["suricata", "ids", "eve"]}}]


class TestConnectorBaseUrlPolicy:
    def test_private_polling_wazuh_rejected_without_allowlist(self, tmp_dir):
        mgr = DetectionConnectorManager(persist_dir=tmp_dir)
        try:
            with _private_dns(), pytest.raises(ValueError, match="non-public"):
                mgr.add_connector(
                    name="wz", connector_type="wazuh", base_url="https://wazuh.corp.local",
                    config={"poll_enabled": True},
                )
        finally:
            mgr.close()

    def test_private_push_only_wazuh_accepted_without_allowlist(self, tmp_dir):
        # Push-only connectors never make outbound requests, so the host
        # installer can register the local manager (https://127.0.0.1:55000).
        mgr = DetectionConnectorManager(persist_dir=tmp_dir)
        try:
            row = mgr.add_connector(
                name="wazuh-host", connector_type="wazuh", base_url="https://127.0.0.1:55000",
            )
            assert row["base_url"] == "https://127.0.0.1:55000"
            with pytest.raises(ValueError, match="HTTPS"):
                mgr.add_connector(name="wz", connector_type="wazuh", base_url="http://127.0.0.1:55000")
        finally:
            mgr.close()

    def test_private_wazuh_accepted_when_hostname_allowlisted(self, tmp_dir):
        mgr = DetectionConnectorManager(persist_dir=tmp_dir, allowed_hosts=["wazuh.corp.local"])
        try:
            with _private_dns():
                row = mgr.add_connector(name="wz", connector_type="wazuh", base_url="https://wazuh.corp.local")
            assert row["connector_type"] == "wazuh"
        finally:
            mgr.close()

    def test_private_wazuh_still_requires_https(self, tmp_dir):
        mgr = DetectionConnectorManager(persist_dir=tmp_dir, allowed_hosts=["wazuh.corp.local"])
        try:
            with pytest.raises(ValueError, match="HTTPS"):
                mgr.add_connector(name="wz", connector_type="wazuh", base_url="http://wazuh.corp.local")
        finally:
            mgr.close()

    def test_allowlist_does_not_exempt_other_connector_types(self, tmp_dir):
        mgr = DetectionConnectorManager(persist_dir=tmp_dir, allowed_hosts=["siem.corp.local"])
        try:
            with _private_dns(), pytest.raises(ValueError, match="non-public"):
                mgr.add_connector(name="g", connector_type="generic_rest", base_url="https://siem.corp.local")
        finally:
            mgr.close()

    def test_public_url_still_passes(self, tmp_dir):
        mgr = DetectionConnectorManager(persist_dir=tmp_dir)
        try:
            with _public_dns():
                row = mgr.add_connector(name="wz", connector_type="wazuh", base_url="https://indexer.example.com")
            assert row["base_url"] == "https://indexer.example.com"
        finally:
            mgr.close()


class TestWazuhPush:
    def test_push_ingests_detection_and_queues_wazuh_asset_sighting(self, tmp_dir, monkeypatch):
        monkeypatch.delenv("BLACK_ONYX_ASSET_REGISTRY_URL", raising=False)
        embedding_model = MagicMock()
        embedding_model.get_embedding_dim.return_value = 8
        embedding_model.encode_single.return_value = [0.1] * 8
        qdrant_store = MagicMock()
        qdrant_store.stable_id = staticmethod(lambda key, idx=0: abs(hash(key)) % (2**32))
        watchlist_manager = MagicMock()
        watchlist_manager.check_iocs.return_value = []
        ingestor = Ingestor(
            embedding_model=embedding_model, qdrant_store=qdrant_store, watchlist_manager=watchlist_manager,
        )
        mgr = DetectionConnectorManager(persist_dir=tmp_dir, ingestor=ingestor, allowed_hosts=["wazuh.corp.local"])
        try:
            with _private_dns():
                row = mgr.add_connector(
                    name="wz", connector_type="wazuh", base_url="https://wazuh.corp.local", tenant_id="tenant-a",
                )
            alert = _syscheck_alert()
            result = asyncio.run(mgr.push_detections(row["id"], [alert]))
            assert result["mode"] == "push"
            assert result["processed"] == 1
            assert result["errors"] == 0
            assert qdrant_store.upsert_single.call_count == 1
            assert mgr.detection_key_known("connector:wz:003:550:1714567890.12345")
            replay = asyncio.run(mgr.push_detections(row["id"], [alert]))
            assert replay["skipped"] == 1
            outbox = mgr._conn.execute("SELECT asset_id, hostname, ip_address FROM connector_asset_outbox").fetchall()
            assert [(r["asset_id"], r["hostname"], r["ip_address"]) for r in outbox] == [
                ("wazuh:003", "web-01", "10.0.0.15"),
            ]
        finally:
            mgr.close()


# ------------------------------------------------------------------ shipper


class TestShipperRouting:
    def test_suricata_group_wazuh_alert_is_dropped(self):
        alert = _syscheck_alert()
        alert["rule"]["groups"] = ["ids", "suricata"]
        routing = shipper.classify_wazuh_alert(alert, tenant_id="t", min_level=7)
        assert routing.push is False
        assert routing.host_state is None
        assert routing.agent is None

    def test_level_threshold_controls_push(self):
        alert = _syscheck_alert()
        assert shipper.classify_wazuh_alert(alert, tenant_id="t", min_level=7).push is True
        assert shipper.classify_wazuh_alert(alert, tenant_id="t", min_level=11).push is False

    def test_sysmon_process_alert_yields_push_and_host_state(self):
        alert = _sysmon_alert(1, {
            "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "parentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
            "commandLine": "powershell -enc AAAA", "processId": "4242", "parentProcessId": "100",
            "user": "CORP\\alice", "hashes": "SHA256=" + "F" * 64,
        }, level=12)
        routing = shipper.classify_wazuh_alert(alert, tenant_id="tenant-a", min_level=7)
        assert routing.push is True
        payload = routing.host_state
        assert payload["event_type"] == "host_state.process_event"
        assert payload["asset_id"] == "wazuh:007"
        assert payload["os_family"] == "windows"
        assert payload["process"]["name"] == "powershell.exe"
        assert payload["process"]["parent_name"] == "WINWORD.EXE"
        assert payload["process"]["pid"] == 4242
        assert payload["process"]["hashes"] == {"sha256": "f" * 64}

    def test_sysmon_network_and_dns(self):
        net = shipper.wazuh_host_state_payload(_sysmon_alert(3, {
            "image": "C:\\x\\beacon.exe", "sourceIp": "10.0.0.77", "sourcePort": "50123",
            "destinationIp": "198.51.100.7", "destinationPort": "443", "protocol": "tcp",
        }), "t")
        assert net["event_type"] == "host_state.socket_snapshot"
        assert net["socket"]["local_port"] == 50123
        assert net["socket"]["state"] == "established"
        dns = shipper.wazuh_host_state_payload(_sysmon_alert(22, {
            "image": "C:\\x\\beacon.exe", "queryName": "evil.example",
        }), "t")
        assert dns["event_type"] == "host_state.process_event"
        assert dns["dns_query"] == "evil.example"

    def test_auditd_and_logon_alerts(self):
        audit = _syscheck_alert()
        audit.pop("syscheck")
        audit["data"] = {"audit": {
            "exe": "/tmp/x", "pid": "99", "ppid": "1", "euid": "0",
            "execve": {"a0": "/tmp/x", "a1": "--run", "argc": "2", "a10": "z"},
        }}
        payload = shipper.wazuh_host_state_payload(audit, "t")
        assert payload["os_family"] == "linux"
        assert payload["process"]["cmdline"] == "/tmp/x --run z"
        logon = _sysmon_alert(4625, {"targetUserName": "bob", "logonType": "10", "ipAddress": "203.0.113.9"})
        logon["data"]["win"]["system"]["providerName"] = "Microsoft-Windows-Security-Auditing"
        session = shipper.wazuh_host_state_payload(logon, "t")
        assert session["event_type"] == "host_state.user_session"
        assert session["session"]["action"] == "failed_logon"
        ssh = _syscheck_alert()
        ssh.pop("syscheck")
        ssh["rule"]["groups"] = ["syslog", "sshd", "authentication_success"]
        ssh["data"] = {"dstuser": "deploy", "srcip": "203.0.113.10"}
        assert shipper.wazuh_host_state_payload(ssh, "t")["session"]["action"] == "logon"

    def test_plain_alert_has_no_host_state(self):
        assert shipper.wazuh_host_state_payload(_syscheck_alert(), "t") is None

    def test_suricata_envelope_is_unique_and_stable_ulid(self):
        eve = _suricata_eve()
        first = shipper.suricata_envelope(eve, tenant_id="t", collector_id="c", sensor_id="s", asset_id="sensor-1",
                                          seed="suricata:1:0:line-a")
        again = shipper.suricata_envelope(eve, tenant_id="t", collector_id="c", sensor_id="s", asset_id="sensor-1",
                                          seed="suricata:1:0:line-a")
        other = shipper.suricata_envelope(eve, tenant_id="t", collector_id="c", sensor_id="s", asset_id="sensor-1",
                                          seed="suricata:1:200:line-b")
        assert ULID_RE.match(first["event_id"])
        assert first["event_id"] == again["event_id"]
        assert first["event_id"] != other["event_id"]
        assert first["event_type"] == "suricata.alert"
        assert first["source"] == {"collector_id": "c", "source_type": "suricata"}
        assert first["asset"] == {"asset_id": "sensor-1"}
        assert first["payload"]["alert"]["signature_id"] == 2027865
        assert shipper.suricata_envelope({**eve, "event_type": "flow"}, tenant_id="t", collector_id="c",
                                         sensor_id="s", asset_id="a", seed="x") is None

    def test_agent_status_envelope(self):
        env = shipper.agent_status_envelope(
            tenant_id="t", asset_id="wazuh:001", hostname="h", os_family="linux", collector_id="c",
            source_type="wazuh",
        )
        assert ULID_RE.match(env["event_id"])
        assert env["event_type"] == "host_state.agent_status"
        assert env["payload"]["asset_id"] == "wazuh:001"
        assert "process" not in env["payload"]

    def test_osquery_envelope_flattens_columns(self):
        raw = {
            "name": "pack_incident_response_process_snapshot",
            "hostIdentifier": "host-a",
            "unixTime": 1_720_000_000,
            "columns": {"pid": "42", "name": "bash", "path": "/bin/bash", "cmdline": "bash", "ppid": "1"},
        }
        env = shipper.osquery_envelope(
            raw, tenant_id="t", asset_id="host-a", collector_id="c", hostname="host-a",
            os_family="linux", seed="osquery:1:0:line",
        )
        assert env is not None
        assert ULID_RE.match(env["event_id"])
        assert env["event_type"] == "host_state.process_snapshot"
        assert env["source"] == {"collector_id": "c", "source_type": "osquery"}
        assert env["payload"]["name"] == "process_snapshot"
        assert env["payload"]["pid"] == "42"
        assert env["payload"]["path"] == "/bin/bash"
        assert shipper.osquery_envelope(
            {"name": "unknown_query", "columns": {}},
            tenant_id="t", asset_id="a", collector_id="c", hostname="h", os_family="linux", seed="x",
        ) is None


class _RecordingSender:
    def __init__(self, fail_times: int = 0):
        self.pushes: list[list[dict]] = []
        self.host_states: list[list[dict]] = []
        self.suricatas: list[list[dict]] = []
        self.fail_times = fail_times

    def _maybe_fail(self):
        if self.fail_times:
            self.fail_times -= 1
            raise shipper.DeliveryError("down")

    def connector_push(self, alerts):
        self._maybe_fail()
        self.pushes.append(list(alerts))

    def host_state(self, envelopes):
        if envelopes:
            self.host_states.append(list(envelopes))

    def suricata(self, envelopes):
        if envelopes:
            self._maybe_fail()
            self.suricatas.append(list(envelopes))


def _config(tmp: Path, **overrides) -> shipper.ShipperConfig:
    values = {
        "tenant_id": "tenant-a", "collector_id": "shipper-1", "gateway_url": "https://gw", "ingest_key": "k",
        "sources": {"wazuh", "suricata"}, "state_file": tmp / "state.json",
        "wazuh_alerts_file": tmp / "alerts.json", "suricata_eve_file": tmp / "eve.json",
        "osquery_results_file": tmp / "osqueryd.results.log",
        "tip_url": "https://tip", "connector_id": "cid", "connector_token": "tok",
        "sensor_asset_id": "sensor-1", "sensor_id": "sensor-1", "start_at_end": False,
    }
    values.update(overrides)
    return shipper.ShipperConfig(**values)


class TestShipperDelivery:
    def test_routes_files_and_commits_offsets(self, tmp_path):
        process_alert = _sysmon_alert(1, {"image": "C:\\x\\a.exe", "processId": "1"}, level=12)
        suricata_grouped = _syscheck_alert()
        suricata_grouped["rule"]["groups"] = ["suricata"]
        (tmp_path / "alerts.json").write_text(
            "\n".join(json.dumps(a) for a in (_syscheck_alert(), process_alert, suricata_grouped)) + "\n",
        )
        (tmp_path / "eve.json").write_text(
            json.dumps(_suricata_eve()) + "\n" + json.dumps({"event_type": "flow"}) + "\n",
        )
        sender = _RecordingSender()
        enroller = MagicMock()
        ship = shipper.Shipper(_config(tmp_path), sender=sender, enroller=enroller)
        assert ship.poll_once() is True
        assert [a["rule"]["id"] for a in sender.pushes[0]] == ["550", "61603"]
        assert [e["payload"]["asset_id"] for e in sender.host_states[0]] == ["wazuh:007"]
        assert len(sender.suricatas[0]) == 1
        assert {call.args[0] for call in enroller.submit.call_args_list} == {"wazuh:003", "wazuh:007"}
        enroller.ensure.assert_not_called()
        state = json.loads((tmp_path / "state.json").read_text())
        assert state["wazuh"]["offset"] == (tmp_path / "alerts.json").stat().st_size
        assert ship.poll_once() is False

    def test_failed_delivery_keeps_offset_and_resends_same_event_ids(self, tmp_path):
        (tmp_path / "eve.json").write_text(json.dumps(_suricata_eve()) + "\n")
        sender = _RecordingSender(fail_times=1)
        ship = shipper.Shipper(_config(tmp_path, sources={"suricata"}), sender=sender, enroller=MagicMock())
        with pytest.raises(shipper.DeliveryError):
            ship.poll_once()
        assert ship.tails["suricata"].offset == 0
        ship.poll_once()
        ids_first = [e["event_id"] for e in sender.suricatas[0]]
        retry = shipper.Shipper(_config(tmp_path, sources={"suricata"}, state_file=tmp_path / "s2.json"),
                                sender=_RecordingSender(), enroller=MagicMock())
        retry.poll_once()
        assert [e["event_id"] for e in retry.sender.suricatas[0]] == ids_first

    def test_partial_line_waits_and_truncation_resets(self, tmp_path):
        eve = tmp_path / "eve.json"
        eve.write_text(json.dumps(_suricata_eve()))
        sender = _RecordingSender()
        ship = shipper.Shipper(_config(tmp_path, sources={"suricata"}), sender=sender, enroller=MagicMock())
        assert ship.poll_once() is False
        with eve.open("a") as handle:
            handle.write("\n")
        assert ship.poll_once() is True
        eve.write_text(json.dumps(_suricata_eve(1)) + "\n")
        ship.poll_once()
        assert len(sender.suricatas) == 2

    def test_start_at_end_skips_backlog(self, tmp_path):
        (tmp_path / "eve.json").write_text(json.dumps(_suricata_eve()) + "\n")
        sender = _RecordingSender()
        ship = shipper.Shipper(_config(tmp_path, sources={"suricata"}, start_at_end=True), sender=sender,
                               enroller=MagicMock())
        ship.poll_once()
        assert sender.suricatas == []

    def test_heartbeat_covers_seen_agents_and_sensor(self, tmp_path):
        (tmp_path / "alerts.json").write_text(json.dumps(_syscheck_alert()) + "\n")
        (tmp_path / "eve.json").write_text("")
        sender = _RecordingSender()
        ship = shipper.Shipper(_config(tmp_path), sender=sender, enroller=MagicMock())
        ship.poll_once()
        ship.heartbeat()
        beats = sender.host_states[-1]
        assert {(e["asset"]["asset_id"], e["source"]["source_type"]) for e in beats} == {
            ("wazuh:003", "wazuh"), ("sensor-1", "suricata"),
        }
        assert all(e["event_type"] == "host_state.agent_status" for e in beats)
        ship.heartbeat()
        assert {e["asset"]["asset_id"] for e in sender.host_states[-1]} == {"sensor-1"}

    def test_heartbeat_uses_wazuh_api_agents(self, tmp_path):
        sender = _RecordingSender()
        ship = shipper.Shipper(
            _config(tmp_path, sources={"wazuh"}, wazuh_api_url="https://127.0.0.1:55000",
                    wazuh_api_user="u", wazuh_api_password="p"),
            sender=sender, enroller=MagicMock(),
        )
        agents = [{"id": "000", "name": "manager", "os": {"platform": "ubuntu"}},
                  {"id": "012", "name": "dc-1", "os": {"platform": "windows"}}]
        with patch.object(shipper, "fetch_active_agents", return_value=agents):
            ship.heartbeat()
        beats = {e["asset"]["asset_id"]: e["payload"]["os_family"] for e in sender.host_states[-1]}
        assert beats == {"wazuh:000": "linux", "wazuh:012": "windows"}

    def test_config_validation(self, tmp_path, monkeypatch):
        for key in ("BLACK_ONYX_COLLECTOR_TENANT_ID", "BLACK_ONYX_COLLECTOR_GATEWAY_URL",
                    "BLACK_ONYX_COLLECTOR_INGEST_KEY", "BLACK_ONYX_URL",
                    "BLACK_ONYX_CONNECTOR_ID", "BLACK_ONYX_CONNECTOR_TOKEN",
                    "BLACK_ONYX_COLLECTOR_ASSET_ID", "WAZUH_API_URL"):
            monkeypatch.delenv(key, raising=False)
        monkeypatch.setenv("SHIPPER_SOURCES", "wazuh,suricata")
        with pytest.raises(ValueError, match="BLACK_ONYX_COLLECTOR_TENANT_ID.*BLACK_ONYX_CONNECTOR_TOKEN.*BLACK_ONYX_COLLECTOR_ASSET_ID"):
            shipper.ShipperConfig.from_env()
        monkeypatch.setenv("SHIPPER_SOURCES", "wazuh,bogus")
        with pytest.raises(ValueError, match="bogus"):
            shipper.ShipperConfig.from_env()

    def test_heartbeat_withholds_stale_sensor(self, tmp_path):
        eve = tmp_path / "eve.json"
        eve.write_text("")
        old = eve.stat().st_mtime - 3600
        os.utime(eve, (old, old))
        sender = _RecordingSender()
        ship = shipper.Shipper(_config(tmp_path, sources={"suricata"}), sender=sender, enroller=MagicMock())
        ship.heartbeat()
        assert sender.host_states == []

    def test_wazuh_api_failure_still_sends_sensor_heartbeat(self, tmp_path):
        (tmp_path / "eve.json").write_text("")
        sender = _RecordingSender()
        ship = shipper.Shipper(
            _config(tmp_path, wazuh_api_url="https://127.0.0.1:55000", wazuh_api_user="u", wazuh_api_password="p"),
            sender=sender, enroller=MagicMock(),
        )
        with (
            patch.object(shipper, "fetch_active_agents", side_effect=shipper.DeliveryError("api down")),
            pytest.raises(shipper.DeliveryError, match="api down"),
        ):
            ship.heartbeat()
        assert [e["asset"]["asset_id"] for e in sender.host_states[-1]] == ["sensor-1"]

    def test_api_mode_does_not_accumulate_seen_agents(self, tmp_path):
        (tmp_path / "alerts.json").write_text(json.dumps(_syscheck_alert()) + "\n")
        ship = shipper.Shipper(
            _config(tmp_path, sources={"wazuh"}, wazuh_api_url="https://127.0.0.1:55000",
                    wazuh_api_user="u", wazuh_api_password="p"),
            sender=_RecordingSender(), enroller=MagicMock(),
        )
        ship.poll_once()
        assert ship.agents_seen == {}


class TestShipperRotation:
    def _ship(self, tmp_path, sender, **overrides):
        config = _config(
            tmp_path, sources={"suricata"}, suricata_rotated_glob=str(tmp_path / "eve.json.[0-9]*"), **overrides,
        )
        return shipper.Shipper(config, sender=sender, enroller=MagicMock())

    def test_drains_rotated_file_before_following_new_one(self, tmp_path):
        eve = tmp_path / "eve.json"
        eve.write_text(json.dumps(_suricata_eve(1)) + "\n")
        sender = _RecordingSender()
        ship = self._ship(tmp_path, sender)
        ship.poll_once()
        with eve.open("a") as handle:
            handle.write(json.dumps(_suricata_eve(2)) + "\n")
        eve.rename(tmp_path / "eve.json.1")
        eve.write_text(json.dumps(_suricata_eve(3)) + "\n")
        ship.poll_once()
        ship.poll_once()
        sids = [e["payload"]["alert"]["signature_id"] for batch in sender.suricatas for e in batch]
        assert sids == [1, 2, 3]

    def test_restart_after_rotation_finds_rotated_file(self, tmp_path):
        eve = tmp_path / "eve.json"
        eve.write_text(json.dumps(_suricata_eve(1)) + "\n")
        self._ship(tmp_path, _RecordingSender()).poll_once()
        with eve.open("a") as handle:
            handle.write(json.dumps(_suricata_eve(2)) + "\n")
        eve.rename(tmp_path / "eve.json.1")
        eve.write_text(json.dumps(_suricata_eve(3)) + "\n")
        sender = _RecordingSender()
        restarted = self._ship(tmp_path, sender)
        restarted.poll_once()
        restarted.poll_once()
        sids = [e["payload"]["alert"]["signature_id"] for batch in sender.suricatas for e in batch]
        assert sids == [2, 3]

    def test_copy_truncate_with_longer_content_restarts_at_zero(self, tmp_path):
        eve = tmp_path / "eve.json"
        eve.write_text(json.dumps(_suricata_eve(1)) + "\n")
        sender = _RecordingSender()
        ship = self._ship(tmp_path, sender)
        ship.poll_once()
        inode = eve.stat().st_ino
        longer = "\n".join(json.dumps(_suricata_eve(sid)) for sid in (10, 11, 12)) + "\n"
        with eve.open("r+") as handle:
            handle.truncate(0)
            handle.write(longer)
        assert eve.stat().st_ino == inode
        ship.poll_once()
        sids = [e["payload"]["alert"]["signature_id"] for batch in sender.suricatas for e in batch]
        assert sids == [1, 10, 11, 12]

    def test_skips_oversized_line_and_resumes_at_next(self, tmp_path, monkeypatch):
        monkeypatch.setattr(shipper, "MAX_READ_BYTES", 1024)
        eve = tmp_path / "eve.json"
        assert len(json.dumps(_suricata_eve(1))) < 1024
        eve.write_text(json.dumps(_suricata_eve(1)) + "\n" + "x" * 3000 + "\n" + json.dumps(_suricata_eve(2)) + "\n")
        sender = _RecordingSender()
        ship = self._ship(tmp_path, sender)
        for _ in range(8):
            ship.poll_once()
        sids = [e["payload"]["alert"]["signature_id"] for batch in sender.suricatas for e in batch]
        assert sids == [1, 2]


class TestSenderHttp:
    def _sender(self, tmp_path, **overrides):
        return shipper.Sender(_config(tmp_path, **overrides))

    def test_chunk_by_limits_respects_count_and_bytes(self):
        items = [{"n": i, "pad": "x" * 100} for i in range(10)]
        assert [len(b) for b in shipper.chunk_by_limits(items, 4, 10_000)] == [4, 4, 2]
        by_bytes = shipper.chunk_by_limits(items, 100, 300)
        assert all(len(json.dumps(b, separators=(",", ":"))) <= 300 for b in by_bytes)
        assert sum(len(b) for b in by_bytes) == 10

    def test_default_batches_fit_gateway_limit(self, tmp_path, monkeypatch):
        sizes: list[int] = []
        monkeypatch.setattr(shipper, "http_json", lambda *_a, body, **_k: (sizes.append(len(body["events"])), (200, {}))[1])
        self._sender(tmp_path).host_state([{"event_id": str(i)} for i in range(250)])
        assert sizes == [100, 100, 50]

    def test_oversized_batch_is_split_until_accepted(self, tmp_path, monkeypatch):
        sizes: list[int] = []

        def fake(*_args, body, **_kwargs):
            sizes.append(len(body["events"]))
            if len(body["events"]) > 2:
                return 400, "batch exceeds max size"
            return 200, {"accepted": len(body["events"])}

        monkeypatch.setattr(shipper, "http_json", fake)
        self._sender(tmp_path).suricata([{"event_id": str(i)} for i in range(5)])
        assert sum(size for size in sizes if size <= 2) == 5

    def test_single_event_too_large_is_dropped_not_retried(self, tmp_path, monkeypatch):
        monkeypatch.setattr(shipper, "http_json", lambda *_a, **_k: (413, "request body too large or unreadable"))
        self._sender(tmp_path).suricata([{"event_id": "1"}])

    def test_validation_rejects_are_dropped_but_publish_failures_retry(self, tmp_path, monkeypatch):
        rejected = {"accepted": 0, "rejected": 1, "results": [{"status": "rejected", "error": "event_id must be a ULID"}]}
        monkeypatch.setattr(shipper, "http_json", lambda *_a, **_k: (422, rejected))
        self._sender(tmp_path).suricata([{"event_id": "1"}])
        unpublished = {"accepted": 1, "rejected": 1, "results": [{"status": "rejected", "error": "publish failed: kafka"}]}
        monkeypatch.setattr(shipper, "http_json", lambda *_a, **_k: (207, unpublished))
        with pytest.raises(shipper.DeliveryError, match="could not publish"):
            self._sender(tmp_path).suricata([{"event_id": "1"}, {"event_id": "2"}])

    @pytest.mark.parametrize("status", [400, 401, 403, 404, 429, 500, 503])
    def test_other_gateway_errors_retry(self, tmp_path, monkeypatch, status):
        monkeypatch.setattr(shipper, "http_json", lambda *_a, **_k: (status, {"error": "nope"}))
        with pytest.raises(shipper.DeliveryError):
            self._sender(tmp_path).host_state([{"event_id": "1"}])

    def test_connector_push_splits_413_and_retries_other_errors(self, tmp_path, monkeypatch):
        sizes: list[int] = []

        def fake(*_args, body, **_kwargs):
            sizes.append(len(body["detections"]))
            return (413, "too large") if len(body["detections"]) > 1 else (200, {"processed": 1})

        monkeypatch.setattr(shipper, "http_json", fake)
        self._sender(tmp_path).connector_push([{"id": "1"}, {"id": "2"}])
        assert sizes == [2, 1, 1]
        monkeypatch.setattr(shipper, "http_json", lambda *_a, **_k: (422, {"detail": "invalid"}))
        with pytest.raises(shipper.DeliveryError):
            self._sender(tmp_path).connector_push([{"id": "1"}])


class TestAssetEnroller:
    def test_submit_is_non_blocking_and_deduplicated(self, tmp_path, monkeypatch):
        calls: list[tuple[str, str]] = []

        def fake(method, url, **_kwargs):
            calls.append((method, url))
            return (404, None) if method == "GET" else (201, {})

        monkeypatch.setattr(shipper, "http_json", fake)
        enroller = shipper.AssetEnroller(
            _config(tmp_path, asset_registry_url="https://registry", asset_registry_key="key"),
        )
        for _ in range(3):
            enroller.submit("wazuh:003", name="web-01", asset_type="host", ip_address="10.0.0.15", tags={})
        assert calls == []
        enroller.drain()
        assert [method for method, _ in calls] == ["GET", "PUT"]
        assert calls[0][1].endswith("/api/v1/assets/wazuh%3A003")
        enroller.submit("wazuh:003", name="web-01", asset_type="host", ip_address=None, tags={})
        enroller.drain()
        assert len(calls) == 2

    def test_existing_asset_is_never_overwritten(self, tmp_path, monkeypatch):
        calls: list[str] = []
        monkeypatch.setattr(shipper, "http_json", lambda method, *_a, **_k: (calls.append(method), (200, {}))[1])
        enroller = shipper.AssetEnroller(
            _config(tmp_path, asset_registry_url="https://registry", asset_registry_key="key"),
        )
        enroller.submit("wazuh:007", name="ws-07", asset_type="host", ip_address=None, tags={})
        enroller.drain()
        assert calls == ["GET"]
