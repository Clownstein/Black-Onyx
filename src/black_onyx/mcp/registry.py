"""Load MCP tool schemas and dispatch tool calls for in-chat analyst workflows."""

from __future__ import annotations

import importlib
import json
import logging
from functools import lru_cache
from pathlib import Path
from typing import Any, Awaitable, Callable

from black_onyx.auth.service import Principal, Role
from black_onyx.mcp.tool_policy import (
    ToolTier,
    approval_denial_message,
    get_tool_tier,
    is_tool_approved,
)
from black_onyx.mcp.tool_settings import preview_on_allowlist

logger = logging.getLogger(__name__)

ToolHandler = Callable[..., Awaitable[dict[str, Any]]]

_TOOLS_JSON = (
    Path(__file__).resolve().parents[3]
    / "black-onyx-tools"
    / "datasets"
    / "tool_use"
    / "tools.json"
)

# Approval mutation controls are exposed by the official MCP security server.
# The embedded model registry hides them so a model cannot approve its own call;
# Security Lab and paused agent runs provide the reviewed human workflow.
_OFFICIAL_CLIENT_ONLY_TOOLS = frozenset({
    "sec_preview_tool",
    "sec_approve_tool",
    "sec_agent_run_status",
    "sec_agent_run_resume",
})

_TOOL_MODULES: dict[str, tuple[str, str]] = {
    "black_onyx_evidence_search": ("black_onyx_tools.tools.evidence_search", "evidence_search"),
    "black_onyx_ioc_enrich": ("black_onyx_tools.tools.ioc_enrich", "ioc_enrich"),
    "black_onyx_case_assist": ("black_onyx_tools.tools.case_assist", "case_assist"),
    "black_onyx_rule_draft": ("black_onyx_tools.tools.rule_draft", "rule_draft"),
    "black_onyx_attack_map": ("black_onyx_tools.tools.attack_map", "attack_map"),
    "black_onyx_hunt": ("black_onyx_tools.tools.hunt", "hunt"),
    "black_onyx_incident_brief": ("black_onyx_tools.tools.incident_brief", "incident_brief"),
    "black_onyx_asset_context": ("black_onyx_tools.tools.asset_context", "asset_context"),
    "black_onyx_response_draft": ("black_onyx_tools.tools.response_draft", "response_draft"),
    "black_onyx_ti_match": ("black_onyx_tools.tools.ti_match", "ti_match"),
    "black_onyx_watchlist_decay": ("black_onyx_tools.tools.watchlist_decay", "watchlist_decay"),
    "black_onyx_misp_taxii_draft": ("black_onyx_tools.tools.misp_taxii_draft", "misp_taxii_draft"),
    "black_onyx_connector_pulse": ("black_onyx_tools.tools.connector_pulse", "connector_pulse"),
    "black_onyx_feed_digest": ("black_onyx_tools.tools.feed_digest", "feed_digest"),
    "black_onyx_model_ops": ("black_onyx_tools.tools.model_ops", "model_ops"),
    "black_onyx_passive_dns_whois": ("black_onyx_tools.tools.passive_dns_whois", "passive_dns_whois"),
    "black_onyx_url_screenshot_sandbox": ("black_onyx_tools.tools.url_screenshot_sandbox", "url_screenshot_sandbox"),
    "black_onyx_certificate_transparency": ("black_onyx_tools.tools.certificate_transparency", "certificate_transparency"),
}

# ── Security tools (45) dispatched via BFF to security-gateway ──────
# Each entry maps sec_<name> to the sec_tools module; execution goes
# through the PlatformClient to /api/v1/security/tools/<name>.
_SECURITY_TOOL_NAMES: tuple[str, ...] = (
    "sec_Bash", "sec_Read", "sec_Write", "sec_Edit", "sec_Grep", "sec_Glob", "sec_ListFiles",
    "sec_nmap_scan", "sec_sqlmap_scan", "sec_nikto_scan", "sec_whois_lookup",
    "sec_shodan_search", "sec_gobuster_dir", "sec_hydra_brute", "sec_tcpdump_capture",
    "sec_port_scan",
    "sec_checksec", "sec_decompile", "sec_decompile_function", "sec_disassemble",
    "sec_disassemble_binary", "sec_extract_strings", "sec_run_binary", "sec_file_info",
    "sec_search_gadgets", "sec_cyclic_pattern",
    "sec_aes_encrypt", "sec_aes_decrypt", "sec_decode_hex", "sec_decode_base64",
    "sec_encode_base64", "sec_hash_data", "sec_extract_iocs", "sec_compute_threat_score",
    "sec_add_ioc_to_case", "sec_generate_yara_rule", "sec_analyze_pcap",
    "sec_cast_call", "sec_cast_send", "sec_cast_keccak", "sec_compile_contracts",
    "sec_analyze_contract", "sec_get_contract_storage", "sec_check_solved",
    "sec_submit_solution",
)

for _sec_name in _SECURITY_TOOL_NAMES:
    _TOOL_MODULES[_sec_name] = ("black_onyx_tools.tools.sec_tools", "execute_security_tool")

# Read-only security tool actions that viewers may invoke (none currently
# viewers are blocked from all sec_* tools until per-action granularity
# is needed).
_MUTATING_TOOLS = frozenset({
    "black_onyx_case_assist",
    "black_onyx_response_draft",
    "black_onyx_misp_taxii_draft",
})


@lru_cache(maxsize=1)
def load_tool_catalog() -> list[dict[str, Any]]:
    if not _TOOLS_JSON.is_file():
        logger.warning("MCP tools catalog missing at %s", _TOOLS_JSON)
        return []
    catalog = json.loads(_TOOLS_JSON.read_text(encoding="utf-8"))
    return [
        item
        for item in catalog
        if (item.get("function") or {}).get("name") not in _OFFICIAL_CLIENT_ONLY_TOOLS
    ]


def tool_catalog_summary() -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for item in load_tool_catalog():
        fn = (item.get("function") or {}) if item.get("type") == "function" else item.get("function", {})
        if not fn and "function" in item:
            fn = item["function"]
        name = str(fn.get("name") or "")
        if name:
            rows.append({"name": name, "description": str(fn.get("description") or "")})
    return rows


def _load_handler(name: str) -> ToolHandler | None:
    spec = _TOOL_MODULES.get(name)
    if not spec:
        return None
    module_name, attr = spec
    try:
        module = importlib.import_module(module_name)
    except ImportError:
        logger.debug("MCP tool module unavailable: %s", module_name)
        return None
    handler = getattr(module, attr, None)
    return handler if callable(handler) else None


def validate_tool_call(
    name: str,
    arguments: dict[str, Any],
    *,
    principal: Principal,
    approved_tools: list[str] | None = None,
) -> str | None:
    """Validate a tool call against role, tier policy, and SOAR guards.

    Returns an error message on failure, None on success.
    """
    if name not in _TOOL_MODULES:
        return f"Unknown tool: {name}"

    # ── Role checks ─────────────────────────────────────────────────
    tier = get_tool_tier(name)
    mutating_read_action = (
        (name == "black_onyx_ti_match" and arguments.get("publish") is True)
        or (name == "black_onyx_feed_digest" and arguments.get("poll") is True)
        or (
            name == "black_onyx_watchlist_decay"
            and str(arguments.get("action") or "summary").lower() == "propose_add"
            and arguments.get("confirm") is True
        )
    )
    if principal.role == Role.VIEWER:
        # Viewers may only invoke read-tier tools, with one pre-existing
        # exception: case_assist read-only actions (list/get) stay available.
        case_assist_readonly = (
            name == "black_onyx_case_assist"
            and str(arguments.get("action") or "get").lower() in {"list", "get"}
        )
        if (tier != ToolTier.READ and not case_assist_readonly) or mutating_read_action:
            return f"Viewer role cannot invoke tier '{tier.value}' tools."
        # Existing platform guard: mutating tool block with case_assist exception.
        if name in _MUTATING_TOOLS:
            action = str(arguments.get("action") or "get").lower()
            readonly = name == "black_onyx_case_assist" and action in {"list", "get"}
            if not readonly:
                return "Viewer role cannot invoke mutating MCP tools."

    # ── SOAR guard (defense in depth) ───────────────────────────────
    if name == "black_onyx_response_draft" and arguments.get("approve"):
        return "response_draft never approves SOAR actions."

    # Action flags are model-supplied data, never evidence of user approval.
    if mutating_read_action:
        return f"{name} mutation must be reviewed in the authenticated app."

    # ── Unified tier approval gate ──────────────────────────────────
    # Effective tier: read-only actions on workspace-write tools (e.g.
    # case_assist list/get) are treated as READ for approval purposes.
    effective_tier = tier
    if name == "black_onyx_case_assist" and str(arguments.get("action") or "get").lower() in {"list", "get"}:
        effective_tier = ToolTier.READ
    if effective_tier != ToolTier.READ:
        if name.startswith("sec_"):
            approval_id = arguments.get("approval_id")
            if isinstance(approval_id, str) and approval_id.strip():
                return None
            # Allow execute_tool to mint a request-bound approval for allowlisted
            # network scanners. Other sec_* tiers still require a human preview.
            if get_tool_tier(name) == ToolTier.NETWORK:
                return None
            return (
                f"Tool '{name}' requires a matching, unused approval_id from "
                "an exact human-reviewed server preview. Tool-name lists and "
                "model confirmation flags do not authorize execution."
            )
        elif not is_tool_approved(
            name, tool_approval="required", approved_tools=approved_tools
        ):
            return approval_denial_message(name)

    return None


async def _mint_allowlist_approval(
    client: Any,
    tool_name: str,
    tool_arguments: dict[str, Any],
    mcp_cfg: Any,
) -> dict[str, Any] | None:
    """Preview and approve a network scanner when every destination is allowlisted."""
    if get_tool_tier(f"sec_{tool_name}") != ToolTier.NETWORK:
        return None
    if not list(getattr(mcp_cfg, "allowed_targets", None) or []):
        return None
    preview_body = {
        "arguments": {
            key: value
            for key, value in tool_arguments.items()
            if key not in {
                "approval_id", "session_id", "request_timeout", "network_profile",
                "destinations", "scope_ports", "lab_profile_id", "resolved_targets",
            }
        },
        "session_id": tool_arguments.get("session_id") or "embedded-chat",
        "timeout": tool_arguments.get("request_timeout") or 60,
        "network_profile": tool_arguments.get("network_profile") or "offline",
    }
    lab_profile_id = tool_arguments.get("lab_profile_id")
    if lab_profile_id is not None:
        preview_body["lab_profile_id"] = lab_profile_id
    preview = await client.tip_post(
        f"/api/v1/security/tools/{tool_name}/preview",
        json=preview_body,
    )
    if not isinstance(preview, dict):
        return None
    destinations = preview.get("destinations") or []
    resolved = preview.get("resolved_targets") or {}
    if not preview_on_allowlist(mcp_cfg, destinations, resolved):
        return None
    approved = await client.tip_post(
        f"/api/v1/security/tools/{tool_name}/approve",
        json={
            "arguments": preview.get("arguments") or preview_body["arguments"],
            "session_id": preview.get("session_id") or preview_body["session_id"],
            "timeout": preview.get("timeout") or preview_body["timeout"],
            "network_profile": preview.get("network_profile"),
            "destinations": destinations,
            "ports": preview.get("ports") or [],
            "lab_profile_id": preview.get("lab_profile_id"),
            "resolved_targets": resolved,
            "preview_hash": preview.get("preview_hash"),
        },
    )
    approval_id = approved.get("approval_id") if isinstance(approved, dict) else None
    if not isinstance(approval_id, str) or not approval_id.strip():
        return None
    return {
        "approval_id": approval_id,
        "arguments": preview.get("arguments") or preview_body["arguments"],
        "session_id": preview.get("session_id") or preview_body["session_id"],
        "timeout": preview.get("timeout") or preview_body["timeout"],
        "network_profile": preview.get("network_profile") or preview_body["network_profile"],
        "destinations": destinations,
        "ports": preview.get("ports") or [],
        "lab_profile_id": preview.get("lab_profile_id"),
        "resolved_targets": resolved,
    }


async def execute_tool(
    client: Any,
    *,
    name: str,
    arguments: dict[str, Any],
    principal: Principal,
    approved_tools: list[str] | None = None,
    mcp_cfg: Any = None,
) -> dict[str, Any]:
    """Execute one MCP tool via a PlatformClient-compatible session client."""
    err = validate_tool_call(name, arguments, principal=principal, approved_tools=approved_tools)
    if err:
        return {"error": err, "tool": name}

    # ── Security tools: dispatch via BFF to security-gateway ────────
    if name.startswith("sec_"):
        tool_name = name[4:]  # strip sec_ prefix
        tool_arguments = dict(arguments)
        if get_tool_tier(name) != ToolTier.READ and not (
            isinstance(tool_arguments.get("approval_id"), str) and str(tool_arguments.get("approval_id")).strip()
        ):
            try:
                minted = await _mint_allowlist_approval(client, tool_name, tool_arguments, mcp_cfg)
            except Exception as exc:
                logger.warning("Allowlist approval for %s failed: %s", name, exc)
                minted = None
            if minted:
                tool_arguments.update({
                    "approval_id": minted["approval_id"],
                    "session_id": minted["session_id"],
                    "request_timeout": minted["timeout"],
                    "network_profile": minted["network_profile"],
                    "destinations": minted["destinations"],
                    "scope_ports": minted["ports"],
                    "lab_profile_id": minted.get("lab_profile_id"),
                    "resolved_targets": minted.get("resolved_targets"),
                })
                if isinstance(minted.get("arguments"), dict):
                    for key, value in minted["arguments"].items():
                        tool_arguments.setdefault(key, value)
            else:
                return {
                    "error": (
                        f"Tool '{name}' requires a matching, unused approval_id from "
                        "an exact human-reviewed server preview. Add the target to "
                        "Settings → MCP tools allowlist, or use Preview → Approve on "
                        "the tool card. Tool-name lists and model confirmation flags "
                        "do not authorize execution."
                    ),
                    "tool": name,
                }
        request = {
            "arguments": {
                key: value
                for key, value in tool_arguments.items()
                if key not in {
                    "approval_id", "session_id", "request_timeout", "network_profile",
                    "destinations", "scope_ports", "lab_profile_id", "resolved_targets",
                }
            },
            "session_id": tool_arguments.get("session_id") or "embedded-chat",
            "timeout": tool_arguments.get("request_timeout") or 60,
            "network_profile": tool_arguments.get("network_profile") or "offline",
            "destinations": tool_arguments.get("destinations") or [],
            "ports": tool_arguments.get("scope_ports") or [],
        }
        for key in ("approval_id", "lab_profile_id", "resolved_targets"):
            if tool_arguments.get(key) is not None:
                request[key] = tool_arguments[key]
        try:
            result = await client.tip_post(
                f"/api/v1/security/tools/{tool_name}",
                json=request,
            )
            return result if isinstance(result, dict) else {"result": result}
        except Exception as exc:
            logger.warning("Security tool %s failed: %s", name, exc)
            return {"error": f"Security tool dispatch failed: {exc}", "tool": name}

    # ── Platform tools: import and call handler directly ───────────
    handler = _load_handler(name)
    if handler is None:
        return {
            "error": (
                f"Tool '{name}' is not available. Install optional MCP deps "
                "(uv sync --extra mcp) to enable black-onyx-tools handlers."
            ),
            "tool": name,
        }

    try:
        result = await handler(client, **arguments)
        return result if isinstance(result, dict) else {"result": result}
    except TypeError as exc:
        return {"error": f"Invalid arguments for {name}: {exc}", "tool": name}
    except Exception as exc:
        logger.exception("MCP tool %s failed", name)
        return {"error": str(exc), "tool": name}
