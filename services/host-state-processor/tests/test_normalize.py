from host_state_processor.normalize import normalize_host_state_event, process_basename


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


def test_process_basename_strips_exe():
    assert process_basename(r"C:\Windows\System32\cmd.exe") == "cmd"
    assert process_basename("powershell.exe") == "powershell"
