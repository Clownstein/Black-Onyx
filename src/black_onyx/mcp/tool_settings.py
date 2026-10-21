"""Per-tool MCP enablement, network scope, and catalog grouping."""
from __future__ import annotations

import ipaddress
import re
from typing import Any, Literal, assert_never

from pydantic import BaseModel, Field, field_validator

NetworkProfile = Literal["lab", "public", "offline"]

TOOL_GROUPS: tuple[tuple[str, str], ...] = (
    ("platform", "Platform"),
    ("sandbox", "Sandbox"),
    ("security", "Network scanners"),
    ("binary", "Binary RE"),
    ("crypto", "Crypto / DFIR"),
    ("web3", "Web3"),
)

_SANDBOX = frozenset({"Bash", "Read", "Write", "Edit", "Grep", "Glob", "ListFiles"})
_SECURITY = frozenset({
    "nmap_scan", "sqlmap_scan", "nikto_scan", "whois_lookup", "shodan_search",
    "gobuster_dir", "hydra_brute", "tcpdump_capture", "port_scan",
})
_BINARY = frozenset({
    "checksec", "decompile", "decompile_function", "disassemble", "disassemble_binary",
    "extract_strings", "run_binary", "file_info", "search_gadgets", "cyclic_pattern",
})
_CRYPTO = frozenset({
    "aes_encrypt", "aes_decrypt", "decode_hex", "decode_base64", "encode_base64",
    "hash_data", "extract_iocs", "compute_threat_score", "add_ioc_to_case",
    "generate_yara_rule", "analyze_pcap",
})
_WEB3 = frozenset({
    "cast_call", "cast_send", "cast_keccak", "compile_contracts", "analyze_contract",
    "get_contract_storage", "check_solved", "submit_solution",
})
NETWORK_SHORT_NAMES = frozenset({
    "nmap_scan", "sqlmap_scan", "nikto_scan", "whois_lookup", "gobuster_dir",
    "hydra_brute", "port_scan", "cast_call", "get_contract_storage",
})
EXECUTION_CONTROL_KEYS = frozenset({
    "approval_id",
    "network_profile",
    "lab_profile_id",
    "destinations",
    "resolved_targets",
    "session_id",
    "request_timeout",
})


class McpToolPolicy(BaseModel):
    enabled: bool = True
    allow_private: bool = True
    allow_public: bool = False
    network_profile: NetworkProfile = "lab"
    timeout_seconds: int = Field(default=60, ge=1, le=300)


class McpToolsConfig(BaseModel):
    """In-chat MCP tool loop (Black Onyx platform and security tools)."""
    enabled: bool = False
    max_tool_rounds: int = Field(default=3, ge=1, le=10)
    lab_profile_id: str = Field(default="anvil", min_length=1, max_length=64, pattern=r"^[a-z0-9][a-z0-9_.-]{0,63}$")
    allowed_targets: list[str] = Field(default_factory=list)
    tools: dict[str, McpToolPolicy] = Field(default_factory=dict)

    @field_validator("tools")
    @classmethod
    def _bound_tools(cls, value: dict[str, McpToolPolicy]) -> dict[str, McpToolPolicy]:
        if len(value) > 128:
            raise ValueError("At most 128 MCP tool policies")
        for name in value:
            if not isinstance(name, str) or not name or len(name) > 80:
                raise ValueError("Invalid MCP tool name")
        return value

    @field_validator("allowed_targets")
    @classmethod
    def _bound_allowed_targets(cls, value: list[str]) -> list[str]:
        if len(value) > 64:
            raise ValueError("At most 64 chat allowlist targets")
        cleaned: list[str] = []
        seen: set[str] = set()
        for raw in value:
            entry = normalize_allowlist_entry(raw)
            if not entry:
                raise ValueError("Invalid chat allowlist target")
            if entry in seen:
                continue
            seen.add(entry)
            cleaned.append(entry)
        return cleaned


def tool_group(name: str) -> str:
    if not name.startswith("sec_"):
        return "platform"
    short = name[4:]
    if short in _SANDBOX:
        return "sandbox"
    if short in _SECURITY:
        return "security"
    if short in _BINARY:
        return "binary"
    if short in _CRYPTO:
        return "crypto"
    if short in _WEB3:
        return "web3"
    return "security"


def default_mcp_tool_policy(name: str) -> McpToolPolicy:
    if name.startswith("sec_"):
        return McpToolPolicy(enabled=False)
    return McpToolPolicy(enabled=True, allow_private=False, network_profile="offline")


def mcp_tool_policy(cfg: Any, name: str) -> McpToolPolicy:
    tools = getattr(cfg, "tools", None) or {}
    stored = tools.get(name) if isinstance(tools, dict) else None
    if isinstance(stored, McpToolPolicy):
        return stored
    if isinstance(stored, dict):
        return McpToolPolicy.model_validate(stored)
    return default_mcp_tool_policy(name)


def filter_tool_catalog(
    catalog: list[dict[str, Any]],
    cfg: Any,
    selected: list[str] | None,
) -> list[dict[str, Any]]:
    if not selected:
        return []
    selected_set = set(selected)
    filtered: list[dict[str, Any]] = []
    for item in catalog:
        fn = item.get("function") or {}
        name = str(fn.get("name") or "")
        if not name:
            continue
        if not mcp_tool_policy(cfg, name).enabled:
            continue
        if name not in selected_set:
            continue
        filtered.append(item)
    return filtered


def apply_mcp_runtime(
    cfg: Any,
    name: str,
    arguments: dict[str, Any],
    selected: list[str] | None,
) -> tuple[dict[str, Any] | None, str | None]:
    if not selected or name not in selected:
        return None, f"Tool '{name}' is not selected for this chat turn."
    policy = mcp_tool_policy(cfg, name)
    if not policy.enabled:
        return None, f"Tool '{name}' is disabled in Settings → MCP tools."
    merged = {key: value for key, value in arguments.items() if key not in EXECUTION_CONTROL_KEYS}
    if name.startswith("sec_"):
        short = name[4:]
        if short in NETWORK_SHORT_NAMES:
            profile = policy.network_profile
            if profile == "public":
                if not policy.allow_public:
                    return None, f"Public targets are disabled for '{name}' in Settings → MCP tools."
                merged["network_profile"] = "public"
            elif profile == "lab":
                if not policy.allow_private:
                    return None, f"Private/lab targets are disabled for '{name}' in Settings → MCP tools."
                merged["network_profile"] = "lab"
                merged["lab_profile_id"] = str(getattr(cfg, "lab_profile_id", "") or "anvil")
            elif profile == "offline":
                merged["network_profile"] = "offline"
            else:
                assert_never(profile)
        merged["request_timeout"] = min(int(policy.timeout_seconds), 300)
        merged["session_id"] = "embedded-chat"
    return merged, None


_HOSTNAME_RE = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$"
)


def normalize_allowlist_entry(raw: str) -> str | None:
    value = str(raw or "").strip().lower().rstrip(".")
    if not value or len(value) > 253 or " " in value:
        return None
    if "/" in value:
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError:
            return None
        if network.version != 4 or network.prefixlen < 24:
            return None
        return str(network)
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        if not _HOSTNAME_RE.fullmatch(value):
            return None
        return value
    if address.version != 4:
        return None
    return str(address)


def _allowlist_networks(entries: list[str]) -> list[ipaddress.IPv4Network]:
    networks: list[ipaddress.IPv4Network] = []
    for entry in entries:
        if "/" in entry:
            networks.append(ipaddress.ip_network(entry, strict=False))
            continue
        try:
            address = ipaddress.ip_address(entry)
        except ValueError:
            continue
        if address.version == 4:
            networks.append(ipaddress.ip_network(f"{address}/32", strict=False))
    return networks


def host_on_allowlist(host: str, entries: list[str]) -> bool:
    normalized = normalize_allowlist_entry(host)
    if not normalized or not entries:
        return False
    if normalized in entries:
        return True
    try:
        address = ipaddress.ip_address(normalized)
    except ValueError:
        return False
    return any(address in network for network in _allowlist_networks(entries))


def preview_on_allowlist(
    cfg: Any,
    destinations: list[str] | None,
    resolved_targets: dict[str, list[str]] | None,
) -> bool:
    entries = list(getattr(cfg, "allowed_targets", None) or [])
    hosts = [str(item) for item in (destinations or []) if str(item).strip()]
    if not entries or not hosts:
        return False
    resolved = resolved_targets if isinstance(resolved_targets, dict) else {}
    for host in hosts:
        if host_on_allowlist(host, entries):
            continue
        ips = [str(ip) for ip in (resolved.get(host) or []) if str(ip).strip()]
        if not ips or not all(host_on_allowlist(ip, entries) for ip in ips):
            return False
    return True


def catalog_rows(catalog: list[dict[str, Any]], cfg: Any) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for item in catalog:
        fn = item.get("function") or {}
        name = str(fn.get("name") or "")
        if not name:
            continue
        policy = mcp_tool_policy(cfg, name)
        rows.append({
            "name": name,
            "description": str(fn.get("description") or ""),
            "group": tool_group(name),
            "enabled": policy.enabled,
            "allow_private": policy.allow_private,
            "allow_public": policy.allow_public,
            "network_profile": policy.network_profile,
            "timeout_seconds": policy.timeout_seconds,
        })
    return rows


def grouped_catalog(catalog: list[dict[str, Any]], cfg: Any) -> list[dict[str, Any]]:
    rows = catalog_rows(catalog, cfg)
    by_group: dict[str, list[dict[str, Any]]] = {key: [] for key, _label in TOOL_GROUPS}
    for row in rows:
        by_group.setdefault(row["group"], []).append(row)
    groups: list[dict[str, Any]] = []
    for key, label in TOOL_GROUPS:
        tools = by_group.get(key) or []
        if tools:
            groups.append({"id": key, "label": label, "tools": tools})
    return groups
