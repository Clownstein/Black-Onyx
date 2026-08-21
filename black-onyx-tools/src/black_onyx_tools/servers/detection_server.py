"""P1 detection MCP server (hunt, incidents, assets, response, TI)."""

from __future__ import annotations

from black_onyx_tools.client import PlatformClient
from black_onyx_tools.config import get_settings
from black_onyx_tools.mcp_app import create_fastmcp, run_mcp
from black_onyx_tools.tools.asset_context import register_asset_context
from black_onyx_tools.tools.hunt import register_hunt
from black_onyx_tools.tools.incident_brief import register_incident_brief
from black_onyx_tools.tools.response_draft import register_response_draft
from black_onyx_tools.tools.ti_match import register_ti_match

DEFAULT_PORT = 8201


def create_app():
    settings = get_settings()
    client = PlatformClient(settings)
    mcp = create_fastmcp("black-onyx-detection", port=DEFAULT_PORT)
    register_hunt(mcp, client)
    register_incident_brief(mcp, client)
    register_asset_context(mcp, client)
    register_response_draft(mcp, client)
    register_ti_match(mcp, client)
    return mcp


def main() -> None:
    run_mcp(create_app(), default_port=DEFAULT_PORT)


if __name__ == "__main__":
    main()
