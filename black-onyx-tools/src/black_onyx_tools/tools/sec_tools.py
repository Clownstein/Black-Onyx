"""Security tool MCP wrappers 45 tools dispatched to the security backend.

Each tool is a thin HTTP wrapper that calls the Black Onyx BFF
(/api/v1/security/*), which proxies to the security-gateway. Tool names
are prefixed with sec_ to distinguish them from platform tools
(black_onyx_*).
"""

from __future__ import annotations

import copy
import inspect
from typing import Any

from mcp.server.fastmcp import FastMCP

from black_onyx_tools.client import PlatformClient

# Tool catalog name → (description, schema)
# Mirrors services/security-gateway/src/security_gateway/tool_catalog.py
SECURITY_TOOL_CATALOG: dict[str, tuple[str, dict[str, Any]]] = {
    # ── Sandbox (7) ─────────────────────────────────────────────────
    "Bash": (
        "Execute a bash command in the sandbox. Returns stdout, stderr, and exit code.",
        {"type": "object", "properties": {
            "command": {"type": "string", "description": "The bash command to execute"},
            "timeout": {"type": "integer", "description": "Timeout in seconds", "default": 30},
        }, "required": ["command"]},
    ),
    "Read": (
        "Read file contents from the sandbox workspace.",
        {"type": "object", "properties": {
            "path": {"type": "string", "description": "File path relative to workspace"},
            "offset": {"type": "integer", "description": "Line to start reading from (1-based)", "default": 1},
            "limit": {"type": "integer", "description": "Maximum lines to read", "default": 2000},
        }, "required": ["path"]},
    ),
    "Write": (
        "Write content to a file in the sandbox workspace, overwriting if it exists.",
        {"type": "object", "properties": {
            "path": {"type": "string", "description": "File path relative to workspace"},
            "content": {"type": "string", "description": "Text content to write"},
        }, "required": ["path", "content"]},
    ),
    "Edit": (
        "Edit a file by replacing old_string with new_string. Requires a unique match unless replace_all is true.",
        {"type": "object", "properties": {
            "path": {"type": "string", "description": "File path relative to workspace"},
            "old_string": {"type": "string", "description": "Exact string to find"},
            "new_string": {"type": "string", "description": "Replacement"},
            "replace_all": {"type": "boolean", "description": "Replace all occurrences", "default": False},
        }, "required": ["path", "old_string", "new_string"]},
    ),
    "Grep": (
        "Search for a regex pattern in files within the sandbox.",
        {"type": "object", "properties": {
            "pattern": {"type": "string", "description": "Regular expression pattern"},
            "path": {"type": "string", "description": "Directory or file to search", "default": "."},
            "glob": {"type": "string", "description": "Glob filter (e.g. *.py)"},
        }, "required": ["pattern"]},
    ),
    "Glob": (
        "Find workspace files matching a glob pattern (supports recursive **).",
        {"type": "object", "properties": {
            "pattern": {"type": "string", "description": "Glob pattern"},
            "path": {"type": "string", "description": "Directory to search", "default": "."},
        }, "required": ["pattern"]},
    ),
    "ListFiles": (
        "List files in a directory.",
        {"type": "object", "properties": {
            "path": {"type": "string", "description": "Directory path", "default": "."},
        }, "required": []},
    ),
    # ── Security (9) ────────────────────────────────────────────────
    "nmap_scan": (
        "Run nmap against a target.",
        {"type": "object", "properties": {
            "target": {"type": "string", "description": "Target host/IP"},
            "ports": {"type": "string", "description": "TCP ports (max 64), or all"},
            "scan": {
                "type": "string",
                "description": "Nmap scan type: version (-sV), connect (-sT), or scripts (-sC -sV)",
                "enum": ["version", "connect", "scripts"],
                "default": "version",
            },
            "timeout": {"type": "integer", "description": "Timeout", "default": 60},
        }, "required": ["target", "ports"]},
    ),
    "sqlmap_scan": (
        "Run sqlmap against a target URL.",
        {"type": "object", "properties": {
            "url": {"type": "string", "description": "Target URL"},
            "timeout": {"type": "integer", "description": "Timeout", "default": 120},
        }, "required": ["url"]},
    ),
    "nikto_scan": (
        "Run nikto against a target.",
        {"type": "object", "properties": {
            "target": {"type": "string", "description": "Target URL/host"},
            "timeout": {"type": "integer", "description": "Timeout", "default": 120},
        }, "required": ["target"]},
    ),
    "whois_lookup": (
        "WHOIS lookup for a domain.",
        {"type": "object", "properties": {
            "domain": {"type": "string", "description": "Domain to look up"},
        }, "required": ["domain"]},
    ),
    "shodan_search": (
        "Perform a bounded Shodan host lookup for an exact public IPv4 address or hostname; requires a configured provider key.",
        {"type": "object", "properties": {
            "query": {"type": "string", "description": "Exact target in ip:<IPv4> or hostname:<public DNS name> form", "maxLength": 512},
        }, "required": ["query"]},
    ),
    "gobuster_dir": (
        "Directory brute-force with gobuster.",
        {"type": "object", "properties": {
            "url": {"type": "string", "description": "Base URL"},
            "timeout": {"type": "integer", "description": "Timeout", "default": 120},
        }, "required": ["url"]},
    ),
    "hydra_brute": (
        "Brute-force with hydra.",
        {"type": "object", "properties": {
            "target": {"type": "string", "description": "Target host"},
            "service": {"type": "string", "description": "Approved service (ssh, ftp, http-get, ...)"},
            "timeout": {"type": "integer", "description": "Maximum run time in seconds", "default": 60},
        }, "required": ["target", "service"]},
    ),
    "tcpdump_capture": (
        "Capture packets with tcpdump.",
        {"type": "object", "properties": {
            "duration": {"type": "integer", "description": "Capture duration (maximum 30 seconds)", "default": 10},
            "filter": {"type": "string", "description": "BPF filter (optional)", "default": ""},
        }},
    ),
    "port_scan": (
        "Quick TCP port scan.",
        {"type": "object", "properties": {
            "target": {"type": "string", "description": "Target host"},
            "ports": {"type": "string", "description": "TCP ports (max 64), or all", "default": "80,443"},
        }, "required": ["target"]},
    ),
    # ── Binary RE (10) ─────────────────────────────────────────────
    "checksec": (
        "Check binary security properties.",
        {"type": "object", "properties": {
            "path": {"type": "string", "description": "Binary path"},
        }, "required": ["path"]},
    ),
    "decompile": (
        "Decompile to radare2 pseudo-C (pdc): one function if given, otherwise every analyzed function.",
        {"type": "object", "properties": {
            "path": {"type": "string", "description": "Binary path"},
            "function": {"type": "string", "description": "Function name (optional)"},
        }, "required": ["path"]},
    ),
    "decompile_function": (
        "Decompile one function to radare2 pseudo-C (pdc).",
        {"type": "object", "properties": {
            "path": {"type": "string", "description": "Binary path"},
            "function": {"type": "string", "description": "Function name"},
        }, "required": ["path", "function"]},
    ),
    "disassemble": (
        "Disassemble a binary with objdump.",
        {"type": "object", "properties": {
            "path": {"type": "string", "description": "Binary path"},
        }, "required": ["path"]},
    ),
    "disassemble_binary": (
        "Disassemble with r2.",
        {"type": "object", "properties": {
            "path": {"type": "string", "description": "Binary path"},
        }, "required": ["path"]},
    ),
    "extract_strings": (
        "Extract strings from a binary.",
        {"type": "object", "properties": {
            "path": {"type": "string", "description": "Binary path"},
            "min_length": {"type": "integer", "description": "Minimum string length", "default": 4},
        }, "required": ["path"]},
    ),
    "run_binary": (
        "Run a binary with timeout.",
        {"type": "object", "properties": {
            "path": {"type": "string", "description": "Binary path"},
            "args": {"type": "string", "description": "Arguments"},
            "timeout": {"type": "integer", "description": "Timeout in seconds", "default": 30},
        }, "required": ["path"]},
    ),
    "file_info": (
        "Get file info (file, readelf).",
        {"type": "object", "properties": {
            "path": {"type": "string", "description": "Binary path"},
        }, "required": ["path"]},
    ),
    "search_gadgets": (
        "Search a binary for ROP gadgets matching an expression (ropper --search).",
        {"type": "object", "properties": {
            "path": {"type": "string", "description": "Binary path"},
            "search": {"type": "string", "description": "Gadget expression, e.g. 'pop rdi; ret'"},
        }, "required": ["path", "search"]},
    ),
    "cyclic_pattern": (
        "Generate cyclic pattern for offset finding.",
        {"type": "object", "properties": {
            "size": {"type": "integer", "description": "Pattern size", "default": 100},
        }, "required": []},
    ),
    # ── Crypto/DFIR (11) ───────────────────────────────────────────
    "aes_encrypt": (
        "AES-GCM encrypt data with a key.",
        {"type": "object", "properties": {
            "data": {"type": "string", "description": "Plaintext data"},
            "key": {"type": "string", "description": "Encryption key (hex)"},
        }, "required": ["data", "key"]},
    ),
    "aes_decrypt": (
        "AES-GCM decrypt data with a key.",
        {"type": "object", "properties": {
            "data": {"type": "string", "description": "Base64 ciphertext"},
            "key": {"type": "string", "description": "Decryption key (hex)"},
        }, "required": ["data", "key"]},
    ),
    "decode_hex": (
        "Decode hex to ASCII.",
        {"type": "object", "properties": {
            "data": {"type": "string", "description": "Hex string"},
        }, "required": ["data"]},
    ),
    "decode_base64": (
        "Decode base64.",
        {"type": "object", "properties": {
            "data": {"type": "string", "description": "Base64 string"},
        }, "required": ["data"]},
    ),
    "encode_base64": (
        "Encode to base64.",
        {"type": "object", "properties": {
            "data": {"type": "string", "description": "Plain data"},
        }, "required": ["data"]},
    ),
    "hash_data": (
        "Hash data (md5/sha1/sha256/sha512).",
        {"type": "object", "properties": {
            "data": {"type": "string", "description": "Data to hash"},
            "algorithm": {"type": "string", "description": "Hash algorithm", "default": "sha256"},
        }, "required": ["data"]},
    ),
    "extract_iocs": (
        "Extract IOCs from text (IPs, emails, URLs, hashes).",
        {"type": "object", "properties": {
            "text": {"type": "string", "description": "Text to extract IOCs from"},
        }, "required": ["text"]},
    ),
    "compute_threat_score": (
        "Compute composite threat score from IOC enrichment data.",
        {"type": "object", "properties": {
            "iocs": {"type": "string", "description": "JSON array of IOCs with confidence scores"},
        }, "required": ["iocs"]},
    ),
    "add_ioc_to_case": (
        "Add IOC to a case file.",
        {"type": "object", "properties": {
            "case_id": {"type": "string", "description": "Case ID"},
            "ioc_type": {"type": "string", "description": "IOC type"},
            "ioc_value": {"type": "string", "description": "IOC value"},
        }, "required": ["case_id", "ioc_type", "ioc_value"]},
    ),
    "generate_yara_rule": (
        "Generate and compile a YARA rule.",
        {"type": "object", "properties": {
            "name": {"type": "string", "description": "Rule name"},
            "strings": {"type": "string", "description": "String patterns"},
            "condition": {"type": "string", "description": "YARA condition"},
        }, "required": ["name", "strings", "condition"]},
    ),
    "analyze_pcap": (
        "Analyze a PCAP with tshark.",
        {"type": "object", "properties": {
            "path": {"type": "string", "description": "PCAP file path"},
            "filter": {"type": "string", "description": "Display filter"},
        }, "required": ["path"]},
    ),
    # ── Web3 (8) ───────────────────────────────────────────────────
    "cast_call": (
        "Read-only Ethereum contract call.",
        {"type": "object", "properties": {
            "to": {"type": "string", "description": "Contract address"},
            "data": {"type": "string", "description": "Calldata (hex)"},
            "rpc_url": {"type": "string", "description": "RPC URL"},
        }, "required": ["to", "data", "rpc_url"]},
    ),
    "cast_send": (
        "Send an approved transaction only to an owned Anvil lab using its unlocked test account; no signing key enters the tool job.",
        {"type": "object", "properties": {
            "to": {"type": "string", "description": "20-byte recipient address", "pattern": "^0x[0-9a-fA-F]{40}$"},
            "sender": {"type": "string", "description": "20-byte sender address unlocked by the registered Anvil node", "pattern": "^0x[0-9a-fA-F]{40}$"},
            "data": {"type": "string", "description": "Hex calldata (maximum 64 KiB)", "maxLength": 131074},
            "value": {"type": "string", "description": "Unsigned value in wei", "default": "0", "maxLength": 78},
            "rpc_url": {"type": "string", "description": "Literal private IPv4 Anvil endpoint on TCP 8545", "maxLength": 256},
        }, "required": ["to", "sender", "data", "value", "rpc_url"]},
    ),
    "cast_keccak": (
        "Compute keccak256 hash.",
        {"type": "object", "properties": {
            "data": {"type": "string", "description": "Data to hash"},
        }, "required": ["data"]},
    ),
    "compile_contracts": (
        "Compile Solidity contracts with forge.",
        {"type": "object", "properties": {
            "path": {"type": "string", "description": "Contract path"},
        }, "required": ["path"]},
    ),
    "analyze_contract": (
        "Analyze a contract with Slither.",
        {"type": "object", "properties": {
            "path": {"type": "string", "description": "Contract path"},
        }, "required": ["path"]},
    ),
    "get_contract_storage": (
        "Read contract storage slots.",
        {"type": "object", "properties": {
            "address": {"type": "string", "description": "Contract address"},
            "slots": {"type": "string", "description": "Storage slot"},
            "rpc_url": {"type": "string", "description": "Approved lab RPC URL"},
        }, "required": ["address", "slots", "rpc_url"]},
    ),
    "check_solved": (
        "Check a registered challenge. Only operator-registered challenge IDs are accepted.",
        {"type": "object", "properties": {
            "challenge_id": {"type": "string", "description": "Registered challenge ID"},
        }, "required": ["challenge_id"]},
    ),
    "submit_solution": (
        "Submit a bounded text/JSON answer to a registered challenge; submitted content is never executed.",
        {"type": "object", "properties": {
            "challenge_id": {"type": "string", "description": "Registered challenge ID"},
            "solution": {"type": "string", "description": "Text or JSON answer; never executed (maximum 16 KiB)", "maxLength": 16384},
        }, "required": ["challenge_id", "solution"]},
    ),
}

SECURITY_CONTROL_CATALOG: dict[str, tuple[str, dict[str, Any]]] = {
    "preview_tool": (
        "Create an exact actor-bound security-tool preview for human review.",
        {"type": "object", "properties": {
            "tool_name": {"type": "string"},
            "arguments": {"type": "object"},
            "session_id": {"type": "string", "default": "mcp-security"},
            "timeout": {"type": "integer", "default": 60},
            "network_profile": {"type": "string", "enum": ["offline", "public", "lab"], "default": "offline"},
            "destinations": {"type": "array", "items": {"type": "string"}},
            "ports": {"type": "array", "items": {"type": "integer"}},
            "lab_profile_id": {"type": "string"},
        }, "required": ["tool_name", "arguments"]},
    ),
    "approve_tool": (
        "Approve an unchanged server-issued preview after explicit human review.",
        {"type": "object", "properties": {
            "tool_name": {"type": "string"},
            "preview": {"type": "object"},
        }, "required": ["tool_name", "preview"]},
    ),
    "agent_run_status": (
        "Read a paused security-agent run and its pending preview.",
        {"type": "object", "properties": {
            "run_id": {"type": "string"},
        }, "required": ["run_id"]},
    ),
    "agent_run_resume": (
        "Resume with a single-use approval ID or deny the pending call.",
        {"type": "object", "properties": {
            "run_id": {"type": "string"},
            "approval_id": {"type": "string"},
            "deny": {"type": "boolean", "default": False},
        }, "required": ["run_id"]},
    ),
}

# These are the only executor calls that the gateway classifies as read tier.
# Every other executor requires a single-use approval bound to its exact preview.
SECURITY_READ_ONLY_TOOLS = frozenset({
    "Read", "Grep", "Glob", "ListFiles",
    "whois_lookup", "shodan_search",
    "checksec", "extract_strings", "file_info",
    "aes_encrypt", "aes_decrypt", "decode_hex", "decode_base64",
    "encode_base64", "hash_data", "extract_iocs", "compute_threat_score",
    "cast_call", "cast_keccak", "get_contract_storage", "check_solved",
})

_EXECUTION_TRANSPORT_PROPERTIES: dict[str, dict[str, Any]] = {
    "session_id": {"type": "string", "default": "mcp-security"},
    "request_timeout": {"type": "integer", "default": 60},
    "network_profile": {
        "type": "string", "enum": ["offline", "public", "lab"], "default": "offline"
    },
    "destinations": {"type": "array", "items": {"type": "string"}},
    "scope_ports": {
        "type": "array",
        "items": {"type": "integer"},
        "description": "Approved destination TCP ports copied from sec_preview_tool",
    },
    "lab_profile_id": {"type": "string"},
    "resolved_targets": {
        "type": "object",
        "description": "Pinned target map copied unchanged from sec_preview_tool",
    },
}
_EXECUTION_TRANSPORT_NAMES = frozenset(_EXECUTION_TRANSPORT_PROPERTIES) | {"approval_id"}


def public_security_tool_schema(tool_name: str) -> dict[str, Any]:
    """Return the MCP schema, including approval metadata when required."""
    if tool_name not in SECURITY_TOOL_CATALOG:
        raise ValueError("unknown security tool")
    schema = copy.deepcopy(SECURITY_TOOL_CATALOG[tool_name][1])
    schema.setdefault("properties", {}).update(copy.deepcopy(_EXECUTION_TRANSPORT_PROPERTIES))
    if tool_name not in SECURITY_READ_ONLY_TOOLS:
        schema.setdefault("properties", {})["approval_id"] = {
            "type": "string",
            "description": (
                "Short-lived single-use ID returned by sec_approve_tool for the "
                "exact unchanged server preview"
            ),
        }
    return schema

# Type mapping for building function signatures
_TYPE_MAP: dict[str, type] = {
    "string": str,
    "integer": int,
    "number": float,
    "boolean": bool,
    "array": list,
    "object": dict,
}

_BFF_ARGUMENT_ALIASES: dict[tuple[str, str], str] = {
    ("cast_send", "sender"): "from",
}


def _build_handler(client: PlatformClient, tool_name: str, schema: dict[str, Any]) -> Any:
    """Build an async handler function for a single security tool."""
    properties: dict[str, Any] = schema.get("properties", {})
    required: list[str] = schema.get("required", [])

    async def _handler(**kwargs: Any) -> dict[str, Any]:
        # Filter to only known params
        payload = {
            _BFF_ARGUMENT_ALIASES.get((tool_name, k), k): v
            for k, v in kwargs.items()
            if k in properties and k not in _EXECUTION_TRANSPORT_NAMES and v is not None
        }
        approval_id = kwargs.get("approval_id")
        # Validate required params
        for req in required:
            forwarded_name = _BFF_ARGUMENT_ALIASES.get((tool_name, req), req)
            if forwarded_name not in payload:
                return {"status": "error", "error": f"Missing required argument: {req}"}
        request = {
            "arguments": payload,
            "session_id": kwargs.get("session_id") or "mcp-security",
            "timeout": kwargs.get("request_timeout") or 60,
            "network_profile": kwargs.get("network_profile") or "offline",
            "destinations": kwargs.get("destinations") or [],
            "ports": kwargs.get("scope_ports") or [],
        }
        if kwargs.get("lab_profile_id"):
            request["lab_profile_id"] = kwargs["lab_profile_id"]
        if isinstance(kwargs.get("resolved_targets"), dict):
            request["resolved_targets"] = kwargs["resolved_targets"]
        if isinstance(approval_id, str) and approval_id:
            request["approval_id"] = approval_id
        return await client.tip_post(f"/api/v1/security/tools/{tool_name}", json=request)

    _handler.__name__ = f"sec_{tool_name}"
    _handler.__doc__ = SECURITY_TOOL_CATALOG[tool_name][0]
    return _handler, properties, required


async def execute_security_tool(client: PlatformClient, **kwargs: Any) -> dict[str, Any]:
    """Dispatch a security tool call through the BFF to the security-gateway.

    Called by the in-chat MCP registry for sec_* tools. The tool name is
    extracted from the module-level current_tool context or passed as
    `tool_name` in kwargs.
    """
    tool_name = kwargs.pop("tool_name", "")
    if not tool_name:
        return {"status": "error", "error": "No tool_name provided for security dispatch"}
    if tool_name not in SECURITY_TOOL_CATALOG:
        return {"status": "error", "error": f"Unknown security tool: {tool_name}"}
    approval_id = kwargs.pop("approval_id", None)
    session_id = kwargs.pop("session_id", "mcp-security")
    timeout = kwargs.pop("request_timeout", 60)
    network_profile = kwargs.pop("network_profile", "offline")
    destinations = kwargs.pop("destinations", None)
    scope_ports = kwargs.pop("scope_ports", None)
    lab_profile_id = kwargs.pop("lab_profile_id", None)
    resolved_targets = kwargs.pop("resolved_targets", None)
    payload = {k: v for k, v in kwargs.items() if v is not None}
    request = {
        "arguments": payload,
        "session_id": session_id,
        "timeout": timeout,
        "network_profile": network_profile,
        "destinations": destinations or [],
        "ports": scope_ports or [],
    }
    if lab_profile_id:
        request["lab_profile_id"] = lab_profile_id
    if isinstance(resolved_targets, dict):
        request["resolved_targets"] = resolved_targets
    if isinstance(approval_id, str) and approval_id:
        request["approval_id"] = approval_id
    return await client.tip_post(f"/api/v1/security/tools/{tool_name}", json=request)


def _control_request(
    *,
    arguments: dict[str, Any],
    session_id: str,
    timeout: int,
    network_profile: str,
    destinations: list[str] | None,
    ports: list[int] | None,
    lab_profile_id: str | None,
) -> dict[str, Any]:
    if not isinstance(arguments, dict):
        raise ValueError("arguments must be an object")
    if not isinstance(session_id, str) or not session_id or len(session_id) > 256:
        raise ValueError("session_id is invalid")
    if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 300:
        raise ValueError("timeout must be between 1 and 300 seconds")
    if network_profile not in {"offline", "public", "lab"}:
        raise ValueError("network_profile is invalid")
    request: dict[str, Any] = {
        "arguments": arguments,
        "session_id": session_id,
        "timeout": timeout,
        "network_profile": network_profile,
        "destinations": destinations or [],
        "ports": ports or [],
    }
    if lab_profile_id:
        request["lab_profile_id"] = lab_profile_id
    return request


async def preview_security_tool(
    client: PlatformClient,
    *,
    tool_name: str,
    arguments: dict[str, Any],
    session_id: str = "mcp-security",
    timeout: int = 60,
    network_profile: str = "offline",
    destinations: list[str] | None = None,
    ports: list[int] | None = None,
    lab_profile_id: str | None = None,
) -> dict[str, Any]:
    """Return the gateway's exact, actor-bound preview for human review."""
    if tool_name not in SECURITY_TOOL_CATALOG:
        raise ValueError("unknown security tool")
    request = _control_request(
        arguments=arguments,
        session_id=session_id,
        timeout=timeout,
        network_profile=network_profile,
        destinations=destinations,
        ports=ports,
        lab_profile_id=lab_profile_id,
    )
    return await client.tip_post(
        f"/api/v1/security/tools/{tool_name}/preview", json=request
    )


async def approve_security_tool(
    client: PlatformClient, *, tool_name: str, preview: dict[str, Any]
) -> dict[str, Any]:
    """Approve only a server-issued preview supplied after human review."""
    if tool_name not in SECURITY_TOOL_CATALOG:
        raise ValueError("unknown security tool")
    if not isinstance(preview, dict) or preview.get("tool") != tool_name:
        raise ValueError("preview does not match the requested tool")
    allowed = {
        "arguments", "session_id", "timeout", "network_profile", "destinations",
        "ports", "lab_profile_id", "resolved_targets", "preview_hash",
    }
    request = {key: value for key, value in preview.items() if key in allowed}
    required = {"arguments", "session_id", "timeout", "network_profile", "preview_hash"}
    if not required.issubset(request):
        raise ValueError("preview is incomplete")
    return await client.tip_post(
        f"/api/v1/security/tools/{tool_name}/approve", json=request
    )


async def security_agent_run_status(
    client: PlatformClient, *, run_id: str
) -> dict[str, Any]:
    if not isinstance(run_id, str) or not run_id or len(run_id) > 128:
        raise ValueError("run_id is invalid")
    return await client.tip_get(f"/api/v1/security/agent/runs/{run_id}")


async def resume_security_agent_run(
    client: PlatformClient,
    *,
    run_id: str,
    approval_id: str | None = None,
    deny: bool = False,
) -> dict[str, Any]:
    if not isinstance(run_id, str) or not run_id or len(run_id) > 128:
        raise ValueError("run_id is invalid")
    if deny == bool(approval_id):
        raise ValueError("provide exactly one of approval_id or deny=true")
    body = {"deny": deny}
    if approval_id:
        if len(approval_id) > 128:
            raise ValueError("approval_id is invalid")
        body["approval_id"] = approval_id
    return await client.tip_post(
        f"/api/v1/security/agent/runs/{run_id}/resume", json=body
    )


def register_security_tools(mcp: FastMCP, client: PlatformClient) -> None:
    """Register 45 executors plus explicit approval and run controls.

    Each tool is exposed as sec_<name> and dispatches through the BFF
    to the security-gateway.
    """
    for tool_name, (description, _schema) in SECURITY_TOOL_CATALOG.items():
        schema = public_security_tool_schema(tool_name)
        handler, properties, required = _build_handler(client, tool_name, schema)

        # Build a dynamic function signature from the schema so FastMCP
        # generates correct parameter metadata.
        params = []
        ordered_names = [*required, *(name for name in properties if name not in required)]
        for pname in ordered_names:
            pschema = properties[pname]
            ptype_raw = pschema.get("type", "string")
            py_type = _TYPE_MAP.get(ptype_raw, str)
            if pname in required:
                params.append(
                    inspect.Parameter(
                        pname, inspect.Parameter.POSITIONAL_OR_KEYWORD,
                        annotation=py_type,
                    )
                )
            elif "default" in pschema:
                default = pschema["default"]
                params.append(
                    inspect.Parameter(
                        pname, inspect.Parameter.POSITIONAL_OR_KEYWORD,
                        default=default, annotation=py_type,
                    )
                )
            else:
                # Optional without default
                params.append(
                    inspect.Parameter(
                        pname, inspect.Parameter.POSITIONAL_OR_KEYWORD,
                        default=None, annotation=py_type,
                    )
                )
        # Approval ids are transport metadata, never forwarded as tool
        # arguments or interpreted as authorization until the gateway checks
        # the exact request digest and consumes the single-use record.
        handler.__signature__ = inspect.Signature(params)  # type: ignore[attr-defined]

        mcp.tool(name=f"sec_{tool_name}")(handler)

    async def preview_tool(
        tool_name: str,
        arguments: dict[str, Any],
        session_id: str = "mcp-security",
        timeout: int = 60,
        network_profile: str = "offline",
        destinations: list[str] | None = None,
        ports: list[int] | None = None,
        lab_profile_id: str | None = None,
    ) -> dict[str, Any]:
        return await preview_security_tool(
            client,
            tool_name=tool_name,
            arguments=arguments,
            session_id=session_id,
            timeout=timeout,
            network_profile=network_profile,
            destinations=destinations,
            ports=ports,
            lab_profile_id=lab_profile_id,
        )

    async def approve_tool(
        tool_name: str, preview: dict[str, Any]
    ) -> dict[str, Any]:
        return await approve_security_tool(
            client, tool_name=tool_name, preview=preview
        )

    async def agent_run_status(run_id: str) -> dict[str, Any]:
        return await security_agent_run_status(client, run_id=run_id)

    async def agent_run_resume(
        run_id: str, approval_id: str | None = None, deny: bool = False
    ) -> dict[str, Any]:
        return await resume_security_agent_run(
            client, run_id=run_id, approval_id=approval_id, deny=deny
        )

    mcp.tool(
        name="sec_preview_tool",
        description=SECURITY_CONTROL_CATALOG["preview_tool"][0],
    )(preview_tool)
    mcp.tool(
        name="sec_approve_tool",
        description=SECURITY_CONTROL_CATALOG["approve_tool"][0],
    )(approve_tool)
    mcp.tool(
        name="sec_agent_run_status",
        description=SECURITY_CONTROL_CATALOG["agent_run_status"][0],
    )(agent_run_status)
    mcp.tool(
        name="sec_agent_run_resume",
        description=SECURITY_CONTROL_CATALOG["agent_run_resume"][0],
    )(agent_run_resume)
