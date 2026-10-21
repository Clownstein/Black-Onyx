import importlib.util
import sys
from pathlib import Path

from host_state_processor.normalize import normalize_host_state_event, process_basename
from host_state_processor.rules import run_rules

SHIPPER_PATH = Path(__file__).resolve().parents[3] / "detection" / "collectors" / "shipper" / "black_onyx_shipper.py"


def _load_shipper():
    spec = importlib.util.spec_from_file_location("black_onyx_shipper", SHIPPER_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["black_onyx_shipper"] = module
    spec.loader.exec_module(module)
    return module


def test_normalize_sysmon_process_create():
    event = {
        "tenant_id": "tenant-acme",
        "occurred_at": "2026-07-26T20:41:02.123Z",
        "asset": {"asset_id": "host-payments-03"},
        "payload": {
            "EventID": 1,
            "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "ParentImage": r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
            "CommandLine": "powershell.exe -enc ZgBvAG8A",
            "ProcessId": 4242,
            "ParentProcessId": 1200,
            "User": r"NT AUTHORITY\SYSTEM",
            "Hashes": "SHA256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        },
    }
    normalized = normalize_host_state_event(event)
    assert normalized["event_type"] == "host_state.process_event"
    assert normalized["tenant_id"] == "tenant-acme"
    assert normalized["asset_id"] == "host-payments-03"
    assert normalized["os_family"] == "windows"
    process = normalized["process"]
    assert process["name"].lower().startswith("powershell")
    assert process["parent_name"].lower().startswith("winword")
    assert process["pid"] == 4242
    assert process["ppid"] == 1200
    assert process["hashes"]["sha256"].startswith("e3b0")


def test_normalize_osquery_listening_port():
    event = {
        "tenant_id": "t1",
        "occurred_at": "2026-07-26T20:41:02Z",
        "asset": {"asset_id": "host-1"},
        "payload": {
            "name": "listening_ports",
            "port": 4444,
            "address": "0.0.0.0",
            "protocol": "tcp",
            "pid": 99,
            "process_name": "evil.exe",
        },
    }
    normalized = normalize_host_state_event(event)
    assert normalized["event_type"] == "host_state.socket_snapshot"
    socket = normalized["socket"]
    assert socket["local_port"] == 4444
    assert socket["state"] == "listen"
    assert socket["process_name"] == "evil.exe"


def test_normalize_already_shaped_host_state_event():
    event = {
        "event_type": "host_state.process_event",
        "tenant_id": "tenant-acme",
        "asset_id": "host-payments-03",
        "occurred_at": "2026-07-26T20:41:02.123Z",
        "hostname": "payments-03",
        "os_family": "windows",
        "process": {
            "pid": 4242,
            "ppid": 1200,
            "name": "powershell.exe",
            "path": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "cmdline": "powershell.exe -enc ZgBvAG8A",
            "user": r"NT AUTHORITY\SYSTEM",
            "action": "create",
        },
    }
    normalized = normalize_host_state_event(event)
    assert normalized["asset_id"] == "host-payments-03"
    assert normalized["process"]["name"] == "powershell.exe"


def test_normalize_requires_timestamp():
    try:
        normalize_host_state_event(
            {
                "tenant_id": "t1",
                "asset": {"asset_id": "a1"},
                "payload": {"Image": r"C:\Temp\a.exe", "ParentImage": r"C:\Windows\explorer.exe"},
            }
        )
        raise AssertionError("expected ValueError")
    except ValueError as exc:
        assert "timestamp" in str(exc).lower() or "occurred_at" in str(exc).lower()


def test_agent_status_heartbeat_is_accepted_without_rule_hits():
    event = {
        "tenant_id": "tenant-acme",
        "occurred_at": "2026-07-26T20:41:02Z",
        "asset": {"asset_id": "wazuh:003"},
        "event_type": "host_state.agent_status",
        "payload": {
            "event_type": "host_state.agent_status",
            "tenant_id": "tenant-acme",
            "asset_id": "wazuh:003",
            "occurred_at": "2026-07-26T20:41:02Z",
            "hostname": "web-01",
            "os_family": "linux",
        },
    }
    normalized = normalize_host_state_event(event)
    assert normalized["event_type"] == "host_state.agent_status"
    assert normalized["asset_id"] == "wazuh:003"
    assert "process" not in normalized and "socket" not in normalized
    assert run_rules(normalized, known_listening_ports=set()) == []


def test_shipper_wazuh_sysmon_payload_triggers_parent_child_rule():
    shipper = _load_shipper()
    alert = {
        "timestamp": "2026-07-26T20:41:02.000+0000",
        "rule": {"id": "61603", "level": 3, "groups": ["windows", "sysmon"]},
        "agent": {"id": "007", "name": "ws-07"},
        "data": {"win": {
            "system": {"eventID": "1", "providerName": "Microsoft-Windows-Sysmon"},
            "eventdata": {
                "image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                "parentImage": r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
                "commandLine": "powershell -enc AAAA",
                "processId": "4242",
            },
        }},
    }
    payload = shipper.wazuh_host_state_payload(alert, "tenant-acme")
    envelope = shipper.host_state_envelope(payload, collector_id="shipper-1", seed="x")
    normalized = normalize_host_state_event(envelope)
    assert normalized["asset_id"] == "wazuh:007"
    assert normalized["os_family"] == "windows"
    detectors = {hit["detector"] for hit in run_rules(normalized, known_listening_ports=set())}
    assert "suspicious_parent_child" in detectors


def test_process_basename_strips_exe():
    assert process_basename(r"C:\Windows\System32\cmd.exe") == "cmd"
    assert process_basename("powershell.exe") == "powershell"
