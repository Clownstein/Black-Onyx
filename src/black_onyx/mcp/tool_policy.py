"""Unified tool tier policy fail-closed for unknown tools.

Merged from model-tools/agent/tool_policy.py with Black Onyx platform
tools mapped to tiers. Read-tier tools auto-approve. Platform mutations may
use an explicit approved_tools entry; security executors require a server-
issued request-bound approval ID at the registry boundary.

Tiers (in increasing restriction):
  read auto-approved, no side effects
  workspace-write writes confined to a sandbox workspace
  network outbound network access (scanners, lookups)
  code-execution runs local binaries in the sandbox
  privileged-capture packet capture (NET_RAW/NET_ADMIN)
  transaction blockchain state changes (cast_send)
  lab lab-only tooling (RE, analysis)
  destructive fail-closed default for unknown tools

SOAR containment (black_onyx_response_draft) is always destructive and
additionally never accepts an `approve` argument.
"""
from __future__ import annotations

import logging
import os
from collections.abc import Iterable
from enum import Enum

logger = logging.getLogger(__name__)
_warned_auto_approval = False


class ToolTier(str, Enum):
    READ = "read"
    WORKSPACE_WRITE = "workspace-write"
    NETWORK = "network"
    CODE_EXECUTION = "code-execution"
    PRIVILEGED_CAPTURE = "privileged-capture"
    TRANSACTION = "transaction"
    LAB = "lab"
    DESTRUCTIVE = "destructive"


# Explicit registry for every known tool. Unknown tools default to
# destructive (fail closed) so new tools cannot bypass approval
# accidentally.
TOOL_TIERS: dict[str, ToolTier] = {
    # ── Black Onyx platform tools (18) ──────────────────────────────
    "black_onyx_evidence_search": ToolTier.READ,
    "black_onyx_ioc_enrich": ToolTier.READ,
    "black_onyx_case_assist": ToolTier.WORKSPACE_WRITE,
    "black_onyx_rule_draft": ToolTier.WORKSPACE_WRITE,
    "black_onyx_attack_map": ToolTier.READ,
    "black_onyx_hunt": ToolTier.READ,
    "black_onyx_incident_brief": ToolTier.READ,
    "black_onyx_asset_context": ToolTier.READ,
    "black_onyx_response_draft": ToolTier.DESTRUCTIVE,  # never auto-approve SOAR
    "black_onyx_ti_match": ToolTier.READ,
    "black_onyx_watchlist_decay": ToolTier.READ,
    "black_onyx_misp_taxii_draft": ToolTier.WORKSPACE_WRITE,
    "black_onyx_connector_pulse": ToolTier.NETWORK,
    "black_onyx_feed_digest": ToolTier.READ,
    "black_onyx_model_ops": ToolTier.READ,
    "black_onyx_passive_dns_whois": ToolTier.READ,
    "black_onyx_url_screenshot_sandbox": ToolTier.NETWORK,
    "black_onyx_certificate_transparency": ToolTier.READ,
    # ── Security tools (45) sec_ prefix ────────────────────────────
    # Sandbox
    "sec_Bash": ToolTier.DESTRUCTIVE,
    "sec_Read": ToolTier.READ,
    "sec_Write": ToolTier.WORKSPACE_WRITE,
    "sec_Edit": ToolTier.WORKSPACE_WRITE,
    "sec_Grep": ToolTier.READ,
    "sec_Glob": ToolTier.READ,
    "sec_ListFiles": ToolTier.READ,
    # Security network scanners
    "sec_nmap_scan": ToolTier.NETWORK,
    "sec_nikto_scan": ToolTier.NETWORK,
    "sec_gobuster_dir": ToolTier.NETWORK,
    "sec_port_scan": ToolTier.NETWORK,
    "sec_whois_lookup": ToolTier.READ,
    "sec_shodan_search": ToolTier.READ,
    # Security destructive / lab
    "sec_sqlmap_scan": ToolTier.LAB,
    "sec_hydra_brute": ToolTier.DESTRUCTIVE,
    "sec_tcpdump_capture": ToolTier.PRIVILEGED_CAPTURE,
    # Binary RE
    "sec_checksec": ToolTier.READ,
    "sec_decompile": ToolTier.LAB,
    "sec_decompile_function": ToolTier.LAB,
    "sec_disassemble": ToolTier.LAB,
    "sec_disassemble_binary": ToolTier.LAB,
    "sec_extract_strings": ToolTier.READ,
    "sec_run_binary": ToolTier.DESTRUCTIVE,
    "sec_file_info": ToolTier.READ,
    "sec_search_gadgets": ToolTier.LAB,
    "sec_cyclic_pattern": ToolTier.LAB,
    # Crypto / DFIR
    "sec_aes_encrypt": ToolTier.READ,
    "sec_aes_decrypt": ToolTier.READ,
    "sec_decode_hex": ToolTier.READ,
    "sec_decode_base64": ToolTier.READ,
    "sec_encode_base64": ToolTier.READ,
    "sec_hash_data": ToolTier.READ,
    "sec_extract_iocs": ToolTier.READ,
    "sec_compute_threat_score": ToolTier.READ,
    "sec_add_ioc_to_case": ToolTier.WORKSPACE_WRITE,
    "sec_generate_yara_rule": ToolTier.LAB,
    "sec_analyze_pcap": ToolTier.LAB,
    # Web3
    "sec_cast_call": ToolTier.READ,
    "sec_cast_send": ToolTier.TRANSACTION,
    "sec_cast_keccak": ToolTier.READ,
    "sec_compile_contracts": ToolTier.LAB,
    "sec_analyze_contract": ToolTier.LAB,
    "sec_get_contract_storage": ToolTier.READ,
    "sec_check_solved": ToolTier.READ,
    "sec_submit_solution": ToolTier.DESTRUCTIVE,
}


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def get_tool_tier(tool_name: str) -> ToolTier:
    """Return the tier for a tool. Unknown tools are DESTRUCTIVE (fail closed).

    Context-sensitive overrides:
      - sec_sqlmap_scan elevates to DESTRUCTIVE when SQLMAP_EXPLOIT_MODE=true
    """
    if tool_name == "sec_sqlmap_scan" and _env_bool("SQLMAP_EXPLOIT_MODE", False):
        return ToolTier.DESTRUCTIVE
    return TOOL_TIERS.get(tool_name, ToolTier.DESTRUCTIVE)


def normalize_approved_tools(approved_tools: Iterable[str] | None) -> set[str]:
    """Normalize an approved_tools list into a set of stripped names."""
    if not approved_tools:
        return set()
    return {str(name).strip() for name in approved_tools if str(name).strip()}


def is_tool_approved(
    tool_name: str,
    *,
    tool_approval: str = "required",
    approved_tools: Iterable[str] | None = None,
) -> bool:
    """Return True if the tool may run under the current approval policy.

    ``auto`` is retained for isolated policy tests. ``required`` allows
    read-tier tools, rejects security mutations for request-bound approval at
    the registry boundary, and otherwise accepts an explicit platform-tool
    entry. Unknown modes fail closed.
    """
    global _warned_auto_approval
    mode = (tool_approval or "required").strip().lower()
    if mode == "auto":
        if not _warned_auto_approval:
            logger.warning(
                "TOOL_APPROVAL=auto: every tool is approved; trusted testing only"
            )
            _warned_auto_approval = True
        return True
    if mode != "required":
        logger.error("Unknown TOOL_APPROVAL=%r; failing closed", mode)
        return False
    tier = get_tool_tier(tool_name)
    if tier == ToolTier.READ:
        return True
    if tool_name.startswith("sec_"):
        return False
    return tool_name in normalize_approved_tools(approved_tools)


def approval_denial_message(tool_name: str) -> str:
    """Human-readable denial message including the tool's tier."""
    tier = get_tool_tier(tool_name).value
    if tool_name.startswith("sec_"):
        return (
            f"Tool '{tool_name}' is tier '{tier}' and requires a matching, "
            "unused approval_id from an exact human-reviewed server preview."
        )
    return (
        f"Tool '{tool_name}' is tier '{tier}' and requires approval. "
        f"An authenticated operator must pass approved_tools=[\"{tool_name}\"] on the request."
    )


# Tools that must never appear in the read-tier auto-approve set even if
# someone edits TOOL_TIERS incorrectly defense in depth for SOAR.
_NEVER_AUTO_APPROVE = frozenset({
    "black_onyx_response_draft",
    "sec_Bash",
    "sec_hydra_brute",
    "sec_run_binary",
    "sec_submit_solution",
})


def assert_never_auto_approvable(tool_name: str) -> None:
    """Raise if a tool is configured in a way that would auto-approve SOAR/destructive actions."""
    if tool_name in _NEVER_AUTO_APPROVE and get_tool_tier(tool_name) == ToolTier.READ:
        raise RuntimeError(
            f"Tool {tool_name!r} is configured as read-tier but must never be auto-approved"
        )
