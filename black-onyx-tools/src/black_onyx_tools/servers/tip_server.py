"""P0 TIP MCP server (evidence, IOC, cases, rules, ATT&CK)."""

from __future__ import annotations

from black_onyx_tools.client import PlatformClient
from black_onyx_tools.config import get_settings
from black_onyx_tools.mcp_app import create_fastmcp, run_mcp
from black_onyx_tools.tools.attack_map import register_attack_map
from black_onyx_tools.tools.case_assist import register_case_assist
from black_onyx_tools.tools.evidence_search import register_evidence_search
from black_onyx_tools.tools.ioc_enrich import register_ioc_enrich
from black_onyx_tools.tools.rule_draft import register_rule_draft

DEFAULT_PORT = 8200


def create_app():
    settings = get_settings()
    client = PlatformClient(settings)
    mcp = create_fastmcp("black-onyx-tip", port=DEFAULT_PORT)
    register_evidence_search(mcp, client)
    register_ioc_enrich(mcp, client)
    register_case_assist(mcp, client)
    register_rule_draft(mcp, client)
    register_attack_map(mcp, client)
    return mcp


def main() -> None:
    run_mcp(create_app(), default_port=DEFAULT_PORT)


if __name__ == "__main__":
    main()
