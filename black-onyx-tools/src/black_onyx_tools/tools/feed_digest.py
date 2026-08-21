"""RSS/Atom/TAXII feed digest drafts."""

from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP

from black_onyx_tools.client import PlatformClient


async def feed_digest(
    client: PlatformClient,
    *,
    feed_name: str = "",
    poll: bool = False,
    confirm: bool = False,
) -> dict[str, Any]:
    feeds_payload = await client.tip_get("/api/v1/feeds")
    feeds = feeds_payload.get("feeds") if isinstance(feeds_payload, dict) else feeds_payload
    if feed_name:
        feeds = [f for f in (feeds or []) if str(f.get("name") or f) == feed_name]

    poll_results: list[Any] = []
    if poll:
        if not confirm:
            return {
                "feeds": feeds,
                "poll_results": [],
                "draft": True,
                "message": "Set confirm=True to poll feeds.",
            }
        if feed_name:
            poll_results.append(await client.tip_post(f"/api/v1/feeds/{feed_name}/poll"))
        else:
            poll_results.append(await client.tip_post("/api/v1/feeds/poll-all"))

    digest_lines = ["# Feed digest", ""]
    for feed in feeds or []:
        name = feed.get("name") if isinstance(feed, dict) else str(feed)
        digest_lines.append(f"- **{name}**")
    if poll_results:
        digest_lines.extend(["", "## Poll results", str(poll_results)])

    return {
        "feeds": feeds,
        "poll_results": poll_results,
        "digest_markdown": "\n".join(digest_lines),
    }


def register_feed_digest(mcp: FastMCP, client: PlatformClient) -> None:
    @mcp.tool(name="black_onyx_feed_digest")
    async def feed_digest_tool(
        feed_name: str = "",
        poll: bool = False,
        confirm: bool = False,
    ) -> dict[str, Any]:
        """List configured feeds and optionally poll them for a digest draft."""
        return await feed_digest(client, feed_name=feed_name, poll=poll, confirm=confirm)
