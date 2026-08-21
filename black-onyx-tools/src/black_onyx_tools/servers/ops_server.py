"""P2 ops MCP server (watchlists, CTI ops, connectors, lab tools)."""

from __future__ import annotations

from black_onyx_tools.client import PlatformClient
from black_onyx_tools.config import get_settings
from black_onyx_tools.mcp_app import create_fastmcp, run_mcp
from black_onyx_tools.tools.certificate_transparency import register_certificate_transparency
from black_onyx_tools.tools.connector_pulse import register_connector_pulse
from black_onyx_tools.tools.feed_digest import register_feed_digest
from black_onyx_tools.tools.misp_taxii_draft import register_misp_taxii_draft
from black_onyx_tools.tools.model_ops import register_model_ops
from black_onyx_tools.tools.passive_dns_whois import register_passive_dns_whois
from black_onyx_tools.tools.url_screenshot_sandbox import register_url_screenshot_sandbox
from black_onyx_tools.tools.watchlist_decay import register_watchlist_decay

DEFAULT_PORT = 8202


def create_app():
    settings = get_settings()
    client = PlatformClient(settings)
    mcp = create_fastmcp("black-onyx-ops", port=DEFAULT_PORT)
    register_watchlist_decay(mcp, client)
    register_misp_taxii_draft(mcp, client)
    register_connector_pulse(mcp, client)
    register_feed_digest(mcp, client)
    register_model_ops(mcp, client)
    register_passive_dns_whois(mcp, client)
    register_url_screenshot_sandbox(mcp, client, settings)
    register_certificate_transparency(mcp, client)
    return mcp


def main() -> None:
    run_mcp(create_app(), default_port=DEFAULT_PORT)


if __name__ == "__main__":
    main()
