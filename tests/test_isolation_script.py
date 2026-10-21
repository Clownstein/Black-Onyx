"""Linux Wazuh active-response isolation script, run against stub firewall tools."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "detection" / "collectors" / "wazuh" / "active-response" / "black-onyx-isolate"

pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="bash is required")

STUB = """#!/bin/bash
echo "$(basename "$0") $*" >> "$CALLS"
if [ "$(basename "$0")" = "{fail_tool}" ] && [[ " $* " == *" {fail_arg} "* ]]; then exit 1; fi
case "$(basename "$0")" in
  iptables|ip6tables)
    for a in "$@"; do if [ "$a" = "-C" ] || [ "$a" = "-L" ]; then exit 1; fi; done ;;
  getent) [ "$2" = "manager.corp.local" ] && echo "10.0.0.2 STREAM manager.corp.local" ;;
esac
exit 0
"""


def _setup(tmp_path: Path, *, manager: str = "manager.corp.local", fail_tool: str = "", fail_arg: str = ""):
    wazuh = tmp_path / "ossec"
    (wazuh / "etc").mkdir(parents=True)
    (wazuh / "logs").mkdir()
    (wazuh / "var" / "run").mkdir(parents=True)
    (wazuh / "etc" / "ossec.conf").write_text(
        f"<ossec_config><client><server><address>{manager}</address></server></client></ossec_config>\n",
    )
    stubs = tmp_path / "bin"
    stubs.mkdir()
    for tool in ("iptables", "ip6tables", "getent", "systemd-run", "systemctl"):
        path = stubs / tool
        path.write_text(STUB.replace("{fail_tool}", fail_tool).replace("{fail_arg}", fail_arg))
        path.chmod(0o755)
    calls = tmp_path / "calls.log"
    env = {
        "PATH": f"{stubs}:/usr/bin:/bin", "WAZUH_DIR": str(wazuh), "CALLS": str(calls),
    }
    return env, calls, wazuh / "logs" / "active-responses.log"


def _run(env: dict[str, str], extra_args: list[str], command: str = "add") -> subprocess.CompletedProcess:
    message = json.dumps({"version": 1, "command": command, "parameters": {"extra_args": extra_args}})
    return subprocess.run(
        ["bash", str(SCRIPT)], input=message + "\n", env=env, capture_output=True, text=True, timeout=20,
        check=False,
    )


def _calls(path: Path) -> list[str]:
    return path.read_text().splitlines() if path.exists() else []


def test_isolates_v4_v6_and_forward_with_manager_and_valid_allows(tmp_path):
    env, calls, _log = _setup(tmp_path)
    result = _run(env, ["ttl_minutes=30", "reason=c2 beacon", "allow=10.0.9.0/24", "allow=fd00::5"])
    assert result.returncode == 0, result.stderr
    lines = _calls(calls)
    assert "iptables -w -A BLACK_ONYX_ISOLATE -s 10.0.0.2 -j ACCEPT" in lines
    assert "iptables -w -A BLACK_ONYX_ISOLATE -s 10.0.9.0/24 -j ACCEPT" in lines
    assert "ip6tables -w -A BLACK_ONYX_ISOLATE -s fd00::5 -j ACCEPT" in lines
    assert "ip6tables -w -A BLACK_ONYX_ISOLATE -p ipv6-icmp -j ACCEPT" in lines
    for table in ("iptables", "ip6tables"):
        for chain in ("INPUT", "OUTPUT", "FORWARD"):
            assert f"{table} -w -I {chain} 1 -j BLACK_ONYX_ISOLATE" in lines
        assert f"{table} -w -A BLACK_ONYX_ISOLATE -j DROP" in lines
    assert any(line.startswith("systemctl stop black-onyx-unisolate.timer") for line in lines)
    assert any("--unit=black-onyx-unisolate --on-active=30m" in line for line in lines)


def test_reason_text_cannot_inject_allow_rules(tmp_path):
    env, calls, log = _setup(tmp_path)
    result = _run(env, ["ttl_minutes=30", "reason=x", "allow=0.0.0.0/0;rm", "allow=*"])
    assert result.returncode == 0, result.stderr
    lines = _calls(calls)
    assert not any("0.0.0.0/0" in line for line in lines)
    assert not any(" -s * " in line for line in lines)
    assert "ignoring allow entry" in log.read_text()


def test_unresolvable_manager_refuses_to_isolate(tmp_path):
    env, calls, log = _setup(tmp_path, manager="unknown.corp.local")
    result = _run(env, ["ttl_minutes=30"])
    assert result.returncode == 1
    assert not any("-N BLACK_ONYX_ISOLATE" in line for line in _calls(calls))
    assert "cannot resolve manager" in log.read_text()


def test_failed_rule_restores_instead_of_half_isolating(tmp_path):
    env, calls, log = _setup(tmp_path, fail_tool="ip6tables", fail_arg="DROP")
    result = _run(env, ["ttl_minutes=30"])
    assert result.returncode == 1
    lines = _calls(calls)
    failed_at = lines.index("ip6tables -w -A BLACK_ONYX_ISOLATE -j DROP")
    assert any("-L BLACK_ONYX_ISOLATE" in line for line in lines[failed_at + 1:])
    assert not any("systemd-run" in line for line in lines)
    assert "restoring network access" in log.read_text()


def test_delete_command_cancels_timer_and_restores(tmp_path):
    env, calls, log = _setup(tmp_path)
    result = _run(env, [], command="delete")
    assert result.returncode == 0, result.stderr
    lines = _calls(calls)
    assert any(line.startswith("systemctl stop black-onyx-unisolate.timer") for line in lines)
    assert "isolation removed by delete command" in log.read_text()


def test_invalid_ttl_falls_back_to_default(tmp_path):
    env, calls, _log = _setup(tmp_path)
    assert _run(env, ["ttl_minutes=99999999"]).returncode == 0
    assert any("--on-active=120m" in line for line in _calls(calls))
