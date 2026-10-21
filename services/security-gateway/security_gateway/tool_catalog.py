"""Security tool catalog 45 tools across 5 categories.

Merged from model-tools/mcp_servers/. Each entry has:
  - description: Human-readable description
  - category: sandbox | security | binary | crypto | web3
  - tier: read | workspace-write | network | code-execution | privileged-capture | transaction | lab | destructive
  - parameters: JSON Schema for input validation
  - command_builder: How to build the shell command for the runner
"""
from __future__ import annotations

from typing import Any


def _obj(props: dict[str, Any], required: list[str] | None = None) -> dict[str, Any]:
    schema: dict[str, Any] = {"type": "object", "properties": props}
    if required:
        schema["required"] = required
    return schema


def _s(desc: str = "", default: Any = None) -> dict[str, Any]:
    return {"type": "string", "description": desc, **({"default": default} if default is not None else {})}


def _i(desc: str = "", default: int = 30) -> dict[str, Any]:
    return {"type": "integer", "description": desc, "default": default}


def _b(desc: str = "", default: bool = False) -> dict[str, Any]:
    return {"type": "boolean", "description": desc, "default": default}


TOOL_CATALOG: dict[str, dict[str, Any]] = {
    # ══════════════════════════════════════════════════════════════════
    # Sandbox (7 tools)
    # ══════════════════════════════════════════════════════════════════
    "Bash": {
        "description": "Execute a bash command in the sandbox.",
        "category": "sandbox", "tier": "destructive",
        "parameters": _obj({"command": _s("The bash command to execute"), "timeout": _i("Timeout in seconds")}, ["command"]),
    },
    "Read": {
        "description": "Read file contents from the sandbox workspace.",
        "category": "sandbox", "tier": "read",
        "parameters": _obj({"path": _s("File path relative to workspace"), "offset": _i("Start line (1-based)", 1), "limit": _i("Max lines", 2000)}, ["path"]),
    },
    "Write": {
        "description": "Write content to a file in the sandbox workspace.",
        "category": "sandbox", "tier": "workspace-write",
        "parameters": _obj({"path": _s("File path relative to workspace"), "content": _s("Text content to write")}, ["path", "content"]),
    },
    "Edit": {
        "description": "Edit a file by replacing old_string with new_string.",
        "category": "sandbox", "tier": "workspace-write",
        "parameters": _obj({"path": _s("File path"), "old_string": _s("String to find"), "new_string": _s("Replacement"), "replace_all": _b("Replace all occurrences")}, ["path", "old_string", "new_string"]),
    },
    "Grep": {
        "description": "Search for a regex pattern in files within the sandbox.",
        "category": "sandbox", "tier": "read",
        "parameters": _obj({"pattern": _s("Regex pattern"), "path": _s("Directory to search", "."), "glob": _s("Glob filter")}, ["pattern"]),
    },
    "Glob": {
        "description": "Find workspace files matching a glob pattern (supports recursive **).",
        "category": "sandbox", "tier": "read",
        "parameters": _obj({"pattern": _s("Glob pattern"), "path": _s("Directory", ".")}, ["pattern"]),
    },
    "ListFiles": {
        "description": "List files in a directory.",
        "category": "sandbox", "tier": "read",
        "parameters": _obj({"path": _s("Directory path", ".")}),
    },

    # ══════════════════════════════════════════════════════════════════
    # Security (9 tools)
    # ══════════════════════════════════════════════════════════════════
    "nmap_scan": {
        "description": "Run nmap against a target.",
        "category": "security", "tier": "network",
        "parameters": _obj({
            "target": _s("Target host/IP"),
            "ports": _s("TCP ports (max 64), or all"),
            "scan": {
                "type": "string",
                "description": "Nmap scan type",
                "enum": ["version", "connect", "scripts"],
                "default": "version",
            },
            "timeout": _i("Timeout", 60),
        }, ["target", "ports"]),
    },
    "sqlmap_scan": {
        "description": "Run sqlmap against a target URL.",
        "category": "security", "tier": "lab",
        "parameters": _obj({"url": _s("Target URL"), "timeout": _i("Timeout", 120)}, ["url"]),
    },
    "nikto_scan": {
        "description": "Run nikto against a target.",
        "category": "security", "tier": "network",
        "parameters": _obj({"target": _s("Target URL/host"), "timeout": _i("Timeout", 120)}, ["target"]),
    },
    "whois_lookup": {
        "description": "WHOIS lookup for a domain.",
        "category": "security", "tier": "read",
        "parameters": _obj({"domain": _s("Domain to look up")}, ["domain"]),
    },
    "shodan_search": {
        "description": "Perform a bounded Shodan host lookup for an exact public IPv4 address or hostname; requires a configured provider key.",
        "category": "security", "tier": "read",
        "parameters": _obj({"query": {**_s("Exact target in ip:<IPv4> or hostname:<public DNS name> form"), "maxLength": 512}}, ["query"]),
    },
    "gobuster_dir": {
        "description": "Directory brute-force with gobuster.",
        "category": "security", "tier": "network",
        "parameters": _obj({"url": _s("Base URL"), "timeout": _i("Timeout", 120)}, ["url"]),
    },
    "hydra_brute": {
        "description": "Brute-force with hydra.",
        "category": "security", "tier": "destructive",
        "parameters": _obj({"target": _s("Target host"), "service": _s("Approved service (ssh, ftp, http-get, ...)"), "timeout": _i("Maximum run time in seconds", 60)}, ["target", "service"]),
    },
    "tcpdump_capture": {
        "description": "Capture packets with tcpdump.",
        "category": "security", "tier": "privileged-capture",
        "parameters": _obj({"duration": _i("Capture duration (maximum 30 seconds)", 10), "filter": _s("BPF filter (optional)", "")}),
    },
    "port_scan": {
        "description": "Quick TCP port scan.",
        "category": "security", "tier": "network",
        "parameters": _obj({"target": _s("Target host"), "ports": _s("TCP ports (max 64), or all", "80,443")}, ["target"]),
    },

    # ══════════════════════════════════════════════════════════════════
    # Binary RE (10 tools)
    # ══════════════════════════════════════════════════════════════════
    "checksec": {
        "description": "Check binary security properties.",
        "category": "binary", "tier": "read",
        "parameters": _obj({"path": _s("Binary path")}, ["path"]),
    },
    "decompile": {
        "description": "Decompile to radare2 pseudo-C (pdc): one function if given, otherwise every analyzed function.",
        "category": "binary", "tier": "lab",
        "parameters": _obj({"path": _s("Binary path"), "function": _s("Function name (optional)")}, ["path"]),
    },
    "decompile_function": {
        "description": "Decompile one function to radare2 pseudo-C (pdc).",
        "category": "binary", "tier": "lab",
        "parameters": _obj({"path": _s("Binary path"), "function": _s("Function name")}, ["path", "function"]),
    },
    "disassemble": {
        "description": "Disassemble a binary with objdump.",
        "category": "binary", "tier": "lab",
        "parameters": _obj({"path": _s("Binary path")}, ["path"]),
    },
    "disassemble_binary": {
        "description": "Disassemble with r2.",
        "category": "binary", "tier": "lab",
        "parameters": _obj({"path": _s("Binary path")}, ["path"]),
    },
    "extract_strings": {
        "description": "Extract strings from a binary.",
        "category": "binary", "tier": "read",
        "parameters": _obj({"path": _s("Binary path"), "min_length": _i("Minimum string length", 4)}, ["path"]),
    },
    "run_binary": {
        "description": "Run a binary with timeout.",
        "category": "binary", "tier": "destructive",
        "parameters": _obj({"path": _s("Binary path"), "args": _s("Arguments"), "timeout": _i("Timeout", 30)}, ["path"]),
    },
    "file_info": {
        "description": "Get file info (file, readelf).",
        "category": "binary", "tier": "read",
        "parameters": _obj({"path": _s("Binary path")}, ["path"]),
    },
    "search_gadgets": {
        "description": "Search a binary for ROP gadgets matching an expression (ropper --search).",
        "category": "binary", "tier": "lab",
        "parameters": _obj({"path": _s("Binary path"), "search": _s("Gadget expression, e.g. 'pop rdi; ret'")}, ["path", "search"]),
    },
    "cyclic_pattern": {
        "description": "Generate cyclic pattern for offset finding.",
        "category": "binary", "tier": "lab",
        "parameters": _obj({"size": _i("Pattern size", 100)}),
    },

    # ══════════════════════════════════════════════════════════════════
    # Crypto / DFIR (11 tools)
    # ══════════════════════════════════════════════════════════════════
    "aes_encrypt": {
        "description": "AES-GCM encrypt data with a key.",
        "category": "crypto", "tier": "read",
        "parameters": _obj({"data": _s("Plaintext data"), "key": _s("Encryption key")}, ["data", "key"]),
    },
    "aes_decrypt": {
        "description": "AES-GCM decrypt data with a key.",
        "category": "crypto", "tier": "read",
        "parameters": _obj({"data": _s("Base64 ciphertext"), "key": _s("Decryption key")}, ["data", "key"]),
    },
    "decode_hex": {
        "description": "Decode hex to ASCII.",
        "category": "crypto", "tier": "read",
        "parameters": _obj({"data": _s("Hex string")}, ["data"]),
    },
    "decode_base64": {
        "description": "Decode base64.",
        "category": "crypto", "tier": "read",
        "parameters": _obj({"data": _s("Base64 string")}, ["data"]),
    },
    "encode_base64": {
        "description": "Encode to base64.",
        "category": "crypto", "tier": "read",
        "parameters": _obj({"data": _s("Plain data")}, ["data"]),
    },
    "hash_data": {
        "description": "Hash data (md5/sha1/sha256/sha512).",
        "category": "crypto", "tier": "read",
        "parameters": _obj({"data": _s("Data to hash"), "algorithm": _s("Hash algorithm", "sha256")}, ["data"]),
    },
    "extract_iocs": {
        "description": "Extract IOCs from text.",
        "category": "crypto", "tier": "read",
        "parameters": _obj({"text": _s("Text to extract IOCs from")}, ["text"]),
    },
    "compute_threat_score": {
        "description": "Compute composite threat score from IOC data.",
        "category": "crypto", "tier": "read",
        "parameters": _obj({"iocs": _s("JSON array of IOCs with enrichment")}, ["iocs"]),
    },
    "add_ioc_to_case": {
        "description": "Add IOC to a case file.",
        "category": "crypto", "tier": "workspace-write",
        "parameters": _obj({"case_id": _s("Case ID"), "ioc_type": _s("IOC type"), "ioc_value": _s("IOC value")}, ["case_id", "ioc_type", "ioc_value"]),
    },
    "generate_yara_rule": {
        "description": "Generate YARA source and validate its syntax with the attested yara Python module.",
        "category": "crypto", "tier": "lab",
        "parameters": _obj({"name": _s("Rule name"), "strings": _s("String patterns"), "condition": _s("YARA condition")}, ["name", "strings", "condition"]),
    },
    "analyze_pcap": {
        "description": "Analyze a PCAP with tshark.",
        "category": "crypto", "tier": "lab",
        "parameters": _obj({"path": _s("PCAP file path"), "filter": _s("Display filter")}, ["path"]),
    },

    # ══════════════════════════════════════════════════════════════════
    # Web3 (8 tools)
    # ══════════════════════════════════════════════════════════════════
    "cast_call": {
        "description": "Read-only Ethereum contract call.",
        "category": "web3", "tier": "read",
        "parameters": _obj({"to": _s("Contract address"), "data": _s("Calldata (hex)"), "rpc_url": _s("RPC URL")}, ["to", "data", "rpc_url"]),
    },
    "cast_send": {
        "description": "Send an approved transaction only to an owned Anvil lab using its unlocked test account; no signing key enters the tool job.",
        "category": "web3", "tier": "transaction",
        "parameters": _obj({"to": {**_s("20-byte recipient address"), "pattern": "^0x[0-9a-fA-F]{40}$"}, "from": {**_s("20-byte sender address unlocked by the registered Anvil node"), "pattern": "^0x[0-9a-fA-F]{40}$"}, "data": {**_s("Hex calldata (maximum 64 KiB)"), "maxLength": 131074}, "value": {**_s("Unsigned value in wei"), "default": "0", "maxLength": 78}, "rpc_url": {**_s("Literal private IPv4 Anvil endpoint on port 8545"), "maxLength": 256}}, ["to", "from", "data", "value", "rpc_url"]),
    },
    "cast_keccak": {
        "description": "Compute keccak256 hash.",
        "category": "web3", "tier": "read",
        "parameters": _obj({"data": _s("Data to hash")}, ["data"]),
    },
    "compile_contracts": {
        "description": "Compile Solidity contracts with forge.",
        "category": "web3", "tier": "lab",
        "parameters": _obj({"path": _s("Contract path")}, ["path"]),
    },
    "analyze_contract": {
        "description": "Analyze a contract with Slither.",
        "category": "web3", "tier": "lab",
        "parameters": _obj({"path": _s("Contract path")}, ["path"]),
    },
    "get_contract_storage": {
        "description": "Read contract storage slots.",
        "category": "web3", "tier": "read",
        "parameters": _obj({"address": _s("Contract address"), "slots": _s("Storage slot"), "rpc_url": _s("Approved lab RPC URL")}, ["address", "slots", "rpc_url"]),
    },
    "check_solved": {
        "description": "Check a registered challenge. Only operator-registered challenge IDs are accepted.",
        "category": "web3", "tier": "read",
        "parameters": _obj({"challenge_id": _s("Registered challenge ID")}, ["challenge_id"]),
    },
    "submit_solution": {
        "description": "Submit a bounded text/JSON answer to a registered challenge; submitted content is never executed.",
        "category": "web3", "tier": "destructive",
        "parameters": _obj({"challenge_id": _s("Registered challenge ID"), "solution": {**_s("Text or JSON answer; never executed (maximum 16 KiB)"), "maxLength": 16384}}, ["challenge_id", "solution"]),
    },
}


def tools_by_category() -> dict[str, list[str]]:
    """Group tool names by category."""
    out: dict[str, list[str]] = {}
    for name, spec in TOOL_CATALOG.items():
        out.setdefault(spec["category"], []).append(name)
    return out


def tools_by_tier() -> dict[str, list[str]]:
    """Group tool names by tier."""
    out: dict[str, list[str]] = {}
    for name, spec in TOOL_CATALOG.items():
        out.setdefault(spec["tier"], []).append(name)
    return out
