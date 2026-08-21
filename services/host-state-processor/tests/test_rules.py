from host_state_processor.rules import (
    detect_new_listening_port,
    detect_rare_binary_path,
    detect_suspicious_parent_child,
    run_rules,
)


def test_suspicious_parent_child_office_to_powershell():
    event = {
        "event_type": "host_state.process_event",
        "process": {
            "name": "powershell.exe",
            "path": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "parent_name": "WINWORD.EXE",
            "parent_path": r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
            "cmdline": "powershell.exe -nop -w hidden",
            "pid": 100,
            "ppid": 50,
        },
    }
    hit = detect_suspicious_parent_child(event)
    assert hit is not None
    assert hit["detector"] == "suspicious_parent_child"
    assert "T1059.001" in hit["mitre_techniques"]
    assert hit["score"] >= 0.9


def test_suspicious_parent_child_ignores_benign():
    event = {
        "process": {
            "name": "notepad.exe",
            "parent_name": "explorer.exe",
            "path": r"C:\Windows\System32\notepad.exe",
        }
    }
    assert detect_suspicious_parent_child(event) is None


def test_rare_binary_path_temp_and_tmp():
    win = {
        "process": {
            "name": "payload.exe",
            "path": r"C:\Users\bob\AppData\Local\Temp\payload.exe",
        }
    }
    hit = detect_rare_binary_path(win)
    assert hit is not None
    assert hit["detector"] == "rare_binary_path"
    assert "T1547" in hit["mitre_techniques"]

    linux = {"process": {"name": "dropper", "path": "/tmp/dropper"}}
    assert detect_rare_binary_path(linux) is not None

    system = {
        "process": {
            "name": "svchost.exe",
            "path": r"C:\Windows\System32\svchost.exe",
        }
    }
    assert detect_rare_binary_path(system) is None


def test_new_listening_port_tracks_known():
    event = {
        "socket": {
            "local_port": 4444,
            "state": "listen",
            "protocol": "tcp",
            "process_name": "evil.exe",
            "local_address": "0.0.0.0",
        }
    }
    hit = detect_new_listening_port(event, known_ports=set())
    assert hit is not None
    assert hit["detector"] == "new_listening_port"
    assert "T1049" in hit["mitre_techniques"]
    assert detect_new_listening_port(event, known_ports={4444}) is None

    common = {
        "socket": {
            "local_port": 8080,
            "state": "listen",
            "process_name": "nginx",
        }
    }
    assert detect_new_listening_port(common, known_ports=set()) is None


def test_run_rules_collects_hits():
    event = {
        "process": {
            "name": "cmd.exe",
            "path": r"C:\Users\bob\Downloads\cmd.exe",
            "parent_name": "excel.exe",
            "parent_path": r"C:\Program Files\Microsoft Office\EXCEL.EXE",
        }
    }
    hits = run_rules(event)
    names = {h["detector"] for h in hits}
    assert "suspicious_parent_child" in names
    assert "rare_binary_path" in names
