"""Boundary tests for command representation and one-use approvals."""
from __future__ import annotations

import os
import socket
import subprocess
import sys
from pathlib import Path

import pytest

GATEWAY_ROOT = Path(__file__).resolve().parents[1] / "services" / "security-gateway"
if str(GATEWAY_ROOT) not in sys.path:
    sys.path.insert(0, str(GATEWAY_ROOT))

from security_gateway.approvals import approve, consume, request_digest
from security_gateway.execution_spec import (
    build_execution, derive_network_scope, parse_port_expression, rewrite_agent_scanner_call,
)


def test_metacharacters_are_literal_arguments() -> None:
    supplied = "sample; touch /tmp/should-not-exist"
    execution = build_execution("Grep", {"pattern": supplied, "path": "workspace"})
    assert execution["argv"] == ["grep", "-rn", "--", supplied, "workspace"]
    assert "/bin/sh" not in execution["argv"]


def test_nested_python_input_is_not_source_code() -> None:
    supplied = "');__import__('os').system('false');#"
    execution = build_execution("decode_hex", {"data": supplied})
    assert supplied == execution["stdin"]
    assert supplied not in execution["argv"][2]


def test_trusted_adapters_dispatch_and_transaction_command_is_anvil_only() -> None:
    assert build_execution("submit_solution", {
        "challenge_id": "reference-basic", "solution": "flag{black_onyx_reference}",
    })["argv"] == ["__trusted_adapter__", "submit_solution"]
    assert build_execution("shodan_search", {"query": "ip:8.8.8.8"})["argv"] == [
        "__trusted_adapter__", "shodan_search",
    ]
    with pytest.raises(ValueError, match="exact ip"):
        build_execution("shodan_search", {"query": "port:22"})
    with pytest.raises(ValueError, match="Challenge ID"):
        build_execution("submit_solution", {"challenge_id": "../challenge", "solution": "solve.py"})
    transaction = build_execution("cast_send", {
        "to": "0x0000000000000000000000000000000000000001",
        "from": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
        "data": "0x1234", "value": "0",
        "rpc_url": "http://10.88.0.2:8545",
    })["argv"]
    assert transaction == [
        "python3", "/usr/share/blackonyx/anvil_send.py", "http://10.88.0.2:8545",
        "0x0000000000000000000000000000000000000001",
        "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266", "0x1234", "0",
    ]
    assert not any("PRIVATE_KEY" in arg or "mnemonic" in arg.lower() for arg in transaction)
    assert derive_network_scope("cast_send", {
        "rpc_url": "http://10.88.0.2:8545",
    }) == (["10.88.0.2"], [8545])
    for endpoint in (
        "https://10.88.0.2:8545", "http://127.0.0.1:8545",
        "http://8.8.8.8:8545", "http://10.88.0.2:8546",
        "http://10.88.0.2:8545/rpc", "http://user:pass@10.88.0.2:8545",
    ):
        with pytest.raises(ValueError):
            derive_network_scope("cast_send", {"rpc_url": endpoint})
    with pytest.raises(ValueError, match="recipient"):
        build_execution("cast_send", {"to": "0x1234"})


def test_storage_read_requires_explicit_rpc_url() -> None:
    with pytest.raises(ValueError, match="RPC URL"):
        build_execution("get_contract_storage", {"address": "0x1234", "slots": "0"})
    command = build_execution("get_contract_storage", {
        "address": "0x1234", "slots": "0", "rpc_url": "http://localhost:8545",
    })["argv"]
    assert command[-2:] == ["--rpc-url", "http://localhost:8545"]


def test_network_executor_scope_is_derived_from_safe_arguments() -> None:
    assert derive_network_scope("nmap_scan", {
        "target": "Example.com", "ports": "80,443",
    }) == (["example.com"], [80, 443])
    assert derive_network_scope("gobuster_dir", {
        "url": "https://example.com/app",
    }) == (["example.com"], [443])
    assert derive_network_scope("hydra_brute", {
        "target": "192.0.2.20", "service": "ssh",
    }) == (["192.0.2.20"], [22])
    assert parse_port_expression("80,443,8000-8002") == [80, 443, 8000, 8001, 8002]
    assert parse_port_expression("all") == [0]
    assert parse_port_expression("ALL") == [0]
    with pytest.raises(ValueError, match="64"):
        parse_port_expression("1-1000")
    with pytest.raises(ValueError, match="credentials"):
        derive_network_scope("sqlmap_scan", {
            "url": "https://user:secret@example.com/",
        })
    with pytest.raises(ValueError, match="option"):
        derive_network_scope("port_scan", {"target": "-oN", "ports": "443"})


def test_nmap_and_gobuster_commands_use_bounded_approved_inputs() -> None:
    nmap = build_execution("nmap_scan", {"target": "example.com", "ports": "80,443"})["argv"]
    assert nmap == ["nmap", "-sV", "-p", "80,443", "example.com"]
    nmap_connect = build_execution(
        "nmap_scan", {"target": "example.com", "ports": "22", "scan": "connect"},
    )["argv"]
    assert nmap_connect == ["nmap", "-sT", "-p", "22", "example.com"]
    nmap_scripts = build_execution(
        "nmap_scan", {"target": "example.com", "ports": "80", "scan": "scripts"},
    )["argv"]
    assert nmap_scripts == ["nmap", "-sC", "-sV", "-p", "80", "example.com"]
    nmap_all = build_execution("nmap_scan", {"target": "example.com", "ports": "all"})["argv"]
    assert nmap_all == ["nmap", "-sV", "-p-", "example.com"]
    assert derive_network_scope("nmap_scan", {"target": "example.com", "ports": "all"}) == (
        ["example.com"], [0],
    )
    gobuster = build_execution("gobuster_dir", {"url": "https://example.com/"})["argv"]
    assert gobuster[-2:] == ["-w", "/usr/share/blackonyx/wordlists/common.txt"]
    nikto = build_execution("nikto_scan", {"target": "https://example.com/"})["argv"]
    assert nikto[:2] == ["nikto", "-nocheck"]
    sample = build_execution("run_binary", {"path": "sample.bin", "args": "--help"})["argv"]
    assert sample[:3] == ["timeout", "30", "sample.bin"]
    with pytest.raises(ValueError, match="Network Scanners"):
        build_execution("run_binary", {"path": "nikto", "args": "http://example.com"})
    rewritten_name, rewritten_args = rewrite_agent_scanner_call(
        "run_binary", {"path": "nikto", "args": "http://sec.dw.style"},
    )
    assert rewritten_name == "nikto_scan"
    assert rewritten_args == {"target": "http://sec.dw.style"}
    shell_name, shell_args = rewrite_agent_scanner_call(
        "run_binary", {"path": "/bin/bash", "args": "whoami"},
    )
    assert shell_name == "run_binary"
    assert shell_args == {"path": "whoami"}
    assert build_execution("run_binary", {"path": "whoami"})["argv"][:3] == ["timeout", "30", "whoami"]
    with pytest.raises(ValueError, match="relative"):
        build_execution("run_binary", {"path": "/bin/bash", "args": "whoami"})
    with pytest.raises(ValueError, match="Bash tool"):
        build_execution("run_binary", {"path": "bash", "args": "whoami"})
    abs_name, abs_args = rewrite_agent_scanner_call(
        "run_binary", {"path": "/usr/bin/whoami"},
    )
    assert abs_name == "run_binary" and abs_args["path"] == "whoami"
    bash_name, bash_args = rewrite_agent_scanner_call(
        "run_binary", {"path": "bash", "args": "ls -la /"},
    )
    assert bash_name == "Bash" and bash_args["command"] == "ls -la /"
    assert build_execution("compile_contracts", {"path": "Hello.sol"})["argv"][:2] == ["/usr/local/bin/solc", "--bin"]
    assert build_execution("compile_contracts", {"path": "foundry"})["argv"] == ["forge", "build", "--root", "foundry"]
    assert build_execution("analyze_pcap", {"path": "cap.pcap"})["argv"] == ["tshark", "-r", "cap.pcap"]
    assert build_execution("analyze_pcap", {"path": "cap.pcap", "filter": "http"})["argv"] == ["tshark", "-r", "cap.pcap", "-Y", "http"]
    assert build_execution("analyze_contract", {"path": "Hello.sol"})["argv"] == [
        "slither", "Hello.sol", "--solc", "/usr/local/bin/solc",
        "--solc-disable-warnings", "--fail-none",
    ]


def test_pin_public_targets_rejects_private_and_pins_global(monkeypatch: pytest.MonkeyPatch) -> None:
    from security_gateway.execution_spec import pin_public_targets

    monkeypatch.setattr(
        "security_gateway.execution_spec.socket.getaddrinfo",
        lambda *_args, **_kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 0))],
    )
    assert pin_public_targets(["example.com"]) == {"example.com": ["93.184.216.34"]}
    with pytest.raises(ValueError, match="globally routed"):
        pin_public_targets(["127.0.0.1"])


def test_shodan_adapter_accepts_only_exact_public_lookup_targets() -> None:
    from security_gateway.shodan_adapter import parse_query

    assert parse_query("ip:8.8.8.8") == ("ip", "8.8.8.8")
    assert parse_query("hostname:example.com") == ("hostname", "example.com")
    for value in (
        "port:22", "ip:127.0.0.1", "ip:2606:4700::1111",
        "hostname:service.internal", "hostname:example.com OR port:22",
    ):
        with pytest.raises(ValueError):
            parse_query(value)


@pytest.mark.asyncio
async def test_shodan_adapter_pins_public_provider_address_and_tls_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from security_gateway import shodan_adapter as adapter

    records = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 443))]
    monkeypatch.setattr(adapter.socket, "getaddrinfo", lambda *_args: records)
    calls: list[tuple[str, str, dict]] = []

    class FakeResponse:
        status_code = 200
        is_redirect = False
        headers: dict[str, str] = {}

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def aiter_bytes(self):
            yield b'{"plan":"dev"}'

    class FakeClient:
        def __init__(self, **kwargs):
            assert kwargs["trust_env"] is False
            assert kwargs["follow_redirects"] is False

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        def stream(self, method, url, **kwargs):
            calls.append((method, url, kwargs))
            return FakeResponse()

    monkeypatch.setattr(adapter.httpx, "AsyncClient", FakeClient)
    assert await adapter._get("/api-info", key="provider-key") == {"plan": "dev"}
    method, url, kwargs = calls[0]
    assert method == "GET"
    assert url == "https://93.184.216.34:443/api-info"
    assert kwargs["headers"] == {"Host": "api.shodan.io"}
    assert kwargs["extensions"] == {"sni_hostname": "api.shodan.io"}
    assert kwargs["params"]["key"] == "provider-key"

    monkeypatch.setattr(
        adapter.socket,
        "getaddrinfo",
        lambda *_args: [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("127.0.0.1", 443))],
    )
    with pytest.raises(RuntimeError, match="non-public"):
        await adapter._get("/api-info", key="provider-key")
    assert len(calls) == 1


def test_cast_send_stays_unavailable_until_egress_is_verified(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from security_gateway import app as gateway

    monkeypatch.setenv("ENABLE_CAST_SEND", "true")
    monkeypatch.setattr(gateway, "_egress_ready", False)
    assert gateway._tool_status("cast_send") == "unavailable"


def test_yara_generation_is_structured_and_requires_compiler_attestation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    execution = build_execution("generate_yara_rule", {
        "name": "example_rule", "strings": "alpha\nbeta", "condition": "any of them",
    })
    assert execution["argv"][:2] == ["python3", "-c"]
    compile(execution["argv"][2], "<yara-generator>", "exec")
    assert execution["argv"][-3:] == ["example_rule", "alpha\nbeta", "any of them"]
    assert all("/bin/sh" not in arg for arg in execution["argv"])
    capture = tmp_path / "compiled.yar"
    (tmp_path / "yara.py").write_text(
        "import os\ndef compile(*, source):\n    open(os.environ['YARA_CAPTURE'], 'w').write(source)\n",
        encoding="utf-8",
    )
    environment = dict(os.environ, PYTHONPATH=str(tmp_path), YARA_CAPTURE=str(capture))
    result = subprocess.run(
        [sys.executable, *execution["argv"][1:]], check=True, capture_output=True,
        text=True, encoding="utf-8", env=environment,
    )
    compiled = capture.read_text(encoding="utf-8")
    assert compiled == result.stdout
    assert '$s0 = "alpha"' in compiled
    assert '$s1 = "beta"' in compiled
    assert "any of them" in compiled
    from security_gateway.execution_spec import READ_ONLY_TOOLS
    assert "generate_yara_rule" in READ_ONLY_TOOLS
    with pytest.raises(ValueError, match="identifier"):
        build_execution("generate_yara_rule", {
            "name": "bad;name", "strings": "alpha", "condition": "any of them",
        })

    from security_gateway import app as gateway

    monkeypatch.setattr(gateway, "_attested", {})
    assert gateway._tool_status("generate_yara_rule") == "unavailable"
    monkeypatch.setattr(gateway, "_attested", {"py:yara": True})
    assert gateway._tool_status("generate_yara_rule") == "enabled"


def test_file_path_cannot_leave_workspace() -> None:
    for path in ("../outside", "/etc/passwd", "C:\\Windows\\win.ini", "-option"):
        with pytest.raises(ValueError):
            build_execution("Read", {"path": path})


def test_edit_replace_all_and_grep_filter_are_honored() -> None:
    once = build_execution("Edit", {
        "path": "notes.txt", "old_string": "old", "new_string": "new",
    })
    all_occurrences = build_execution("Edit", {
        "path": "notes.txt", "old_string": "old", "new_string": "new", "replace_all": True,
    })
    assert once["argv"][-1] == "1"
    assert all_occurrences["argv"][-1] == "-1"
    assert "--include=*.txt" in build_execution("Grep", {
        "pattern": "needle", "glob": "*.txt",
    })["argv"]


def test_approval_is_bound_and_single_use(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("SECURITY_APPROVAL_DB", str(tmp_path / "approvals.db"))
    monkeypatch.setenv("SECURITY_GATEWAY_KEY", "test-gateway-key-with-at-least-32-characters")
    body = {"arguments": {"path": "one.txt", "content": "first"}, "session_id": "lab"}
    digest = request_digest("operator", "Write", body)
    assert digest != request_digest("operator", "Write", {**body, "session_id": "other"})
    assert digest != request_digest("operator", "Write", {**body, "timeout": 300})
    approval_id = approve("operator", "Write", body, "operator")
    assert not consume(approval_id, "operator", "Write", {**body, "arguments": {"path": "two.txt", "content": "first"}})
    assert consume(approval_id, "operator", "Write", body)
    assert not consume(approval_id, "operator", "Write", body)


def test_preview_signature_binds_pinned_network_scope(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECURITY_GATEWAY_KEY", "test-gateway-key-with-at-least-32-characters")
    body = {
        "arguments": {"target": "example.com"},
        "session_id": "lab",
        "network_profile": "public",
        "destinations": ["example.com"],
        "ports": [443],
        "resolved_targets": {"example.com": ["93.184.216.34"]},
    }
    digest = request_digest("operator", "nmap_scan", body)
    assert digest != request_digest("operator", "nmap_scan", {**body, "ports": [8443]})
    assert digest != request_digest(
        "operator", "nmap_scan",
        {**body, "resolved_targets": {"example.com": ["1.1.1.1"]}},
    )


def test_catalog_has_no_shell_command_templates() -> None:
    from security_gateway.tool_catalog import TOOL_CATALOG

    # Execution is built as argv by execution_spec; shell templates must not return.
    assert [name for name, spec in TOOL_CATALOG.items() if "command" in spec] == []


def test_tool_status_requires_runner_attestation(monkeypatch: pytest.MonkeyPatch) -> None:
    from security_gateway import app as gateway

    monkeypatch.setattr(gateway, "_attested", {})
    assert gateway._tool_status("Grep") == "enabled"  # baseline image tool
    assert gateway._tool_status("extract_strings") == "unavailable"  # not attested yet
    monkeypatch.setattr(gateway, "_attested", {"bin:strings": True, "bin:ropper": False})
    assert gateway._tool_status("extract_strings") == "enabled"
    assert gateway._tool_status("search_gadgets") == "unavailable"
    # Network tools stay unavailable even when their binary exists (no egress).
    monkeypatch.setattr(gateway, "_attested", {"bin:nmap": True})
    assert gateway._tool_status("nmap_scan") == "unavailable"
    assert gateway._tool_status("shodan_search") == "unavailable"


def test_network_tools_stay_unavailable_with_unverified_bridge(monkeypatch: pytest.MonkeyPatch) -> None:
    from security_gateway import app as gateway

    monkeypatch.setenv("SECURITY_EGRESS_NETWORK", "blackonyx_sandbox_egress")
    monkeypatch.setattr(gateway, "_attested", {"bin:nmap": True})
    assert gateway._tool_status("nmap_scan") == "unavailable"
    assert gateway._tool_status("port_scan") == "unavailable"
    # Unsupported tools stay unavailable regardless.
    assert gateway._tool_status("shodan_search") == "unavailable"
    # Network tools without attested binaries stay unavailable.
    monkeypatch.setattr(gateway, "_attested", {})
    assert gateway._tool_status("nmap_scan") == "unavailable"


def test_validated_request_requires_destinations_for_network(monkeypatch: pytest.MonkeyPatch) -> None:
    from security_gateway import app as gateway

    monkeypatch.setenv("SECURITY_EGRESS_NETWORK", "blackonyx_sandbox_egress")
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as exc:
        gateway._validated_request({
            "arguments": {}, "session_id": "lab",
            "network_profile": "public", "destinations": [],
        })
    assert exc.value.status_code == 503
    with pytest.raises(HTTPException) as exc:
        gateway._validated_request({
            "arguments": {}, "session_id": "lab",
            "network_profile": "public",
            "destinations": ["93.184.216.34"],
        })
    assert exc.value.status_code == 503


def test_validated_request_blocks_egress_without_config(monkeypatch: pytest.MonkeyPatch) -> None:
    from security_gateway import app as gateway

    monkeypatch.delenv("SECURITY_EGRESS_NETWORK", raising=False)
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as exc:
        gateway._validated_request({
            "arguments": {}, "session_id": "lab",
            "network_profile": "public",
            "destinations": ["example.com"],
        })
    assert exc.value.status_code == 503
