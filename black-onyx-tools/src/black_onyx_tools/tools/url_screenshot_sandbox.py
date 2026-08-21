"""Lab-gated URL fetch + optional screenshot (soft-fail without sandbox binary)."""

from __future__ import annotations

import hashlib
import ipaddress
import shutil
import socket
from typing import Any
from urllib.parse import urlparse

import httpx
from mcp.server.fastmcp import FastMCP

from black_onyx_tools.client import PlatformClient
from black_onyx_tools.config import Settings


def _is_blocked_hostname(hostname: str) -> bool:
    host = (hostname or "").strip().lower().rstrip(".")
    if not host:
        return True
    if host in {"localhost", "metadata.google.internal"} or host.endswith(".localhost"):
        return True
    if host.startswith("metadata.") or host.endswith(".internal"):
        return True
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return True
    for info in infos:
        raw = info[4][0]
        try:
            ip = ipaddress.ip_address(raw.split("%", 1)[0])
        except ValueError:
            continue
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
            or str(ip) == "169.254.169.254"
        ):
            return True
    return False


def assert_public_http_url(url: str) -> None:
    """Reject non-http(s) schemes and private/link-local/metadata targets (SSRF)."""
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Only http/https URLs are allowed")
    if parsed.username or parsed.password:
        raise ValueError("URLs with credentials are not allowed")
    if not parsed.hostname or _is_blocked_hostname(parsed.hostname):
        raise ValueError("URL host resolves to a blocked/private address")


async def _try_playwright_screenshot(url: str) -> dict[str, Any] | None:
    """Attempt a Playwright screenshot; abort navigations to blocked hosts."""
    try:
        from playwright.async_api import async_playwright  # type: ignore[import-not-found]
    except ImportError:
        return None

    try:
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(headless=True)
            try:
                page = await browser.new_page(viewport={"width": 1280, "height": 720})

                async def _guard_route(route: Any) -> None:
                    try:
                        assert_public_http_url(route.request.url)
                    except ValueError:
                        await route.abort()
                        return
                    await route.continue_()

                await page.route("**/*", _guard_route)
                # Do not follow cross-host redirects into private space: the route
                # guard re-validates every request URL (including redirect hops).
                await page.goto(url, wait_until="domcontentloaded", timeout=15000)
                # Re-check final URL after navigation (defense in depth).
                assert_public_http_url(page.url)
                png = await page.screenshot(type="png", full_page=False)
            finally:
                await browser.close()
        return {
            "format": "png",
            "sha256": hashlib.sha256(png).hexdigest(),
            "byte_length": len(png),
            "engine": "playwright-chromium",
        }
    except Exception as exc:  # noqa: BLE001 — soft-fail sandbox
        return {"error": str(exc), "engine": "playwright-chromium"}


async def url_screenshot_sandbox(
    settings: Settings,
    client: PlatformClient | None = None,
    *,
    url: str,
    max_bytes: int = 65536,
    case_id: str = "",
    confirm: bool = False,
) -> dict[str, Any]:
    if not settings.tools_allow_sandbox:
        return {
            "enabled": False,
            "message": (
                "URL screenshot sandbox is disabled. "
                "Set BLACK_ONYX_TOOLS_ALLOW_SANDBOX=true to enable lab-gated fetches."
            ),
            "url": url,
        }

    assert_public_http_url(url)

    async with httpx.AsyncClient(
        timeout=httpx.Timeout(10.0, read=15.0),
        follow_redirects=False,
        headers={"User-Agent": "black-onyx-tools/0.1.0"},
    ) as http:
        response = await http.get(url)
        body = response.content[:max_bytes]

    content_hash = hashlib.sha256(body).hexdigest()
    chromium = shutil.which("chromium") or shutil.which("google-chrome") or shutil.which("chrome")
    screenshot = await _try_playwright_screenshot(url)
    if screenshot is None:
        screenshot = {
            "available": False,
            "message": (
                "Screenshot soft-failed: Playwright not installed "
                "(pip install playwright && playwright install chromium). "
                "Content hash from HTTP fetch is still returned."
            ),
            "chromium_on_path": bool(chromium),
        }

    evidence_attach: Any = None
    if case_id and confirm and client is not None:
        note = (
            f"Sandbox fetch of {url}: status={response.status_code}, "
            f"sha256={content_hash}, content_type={response.headers.get('content-type')}"
        )
        evidence_attach = await client.tip_post(
            f"/api/v1/cases/{case_id}/notes",
            json={"content": note},
        )
    elif case_id and not confirm:
        evidence_attach = {
            "draft": True,
            "message": "Pass confirm=True to attach a case note with fetch metadata.",
        }

    return {
        "enabled": True,
        "url": url,
        "status_code": response.status_code,
        "content_type": response.headers.get("content-type"),
        "content_length": len(body),
        "sha256": content_hash,
        "screenshot": screenshot,
        "evidence_attach": evidence_attach,
        "note": "Lab-gated only. Prefer attaching evidence via platform case APIs.",
    }


def register_url_screenshot_sandbox(mcp: FastMCP, client: PlatformClient, settings: Settings) -> None:
    @mcp.tool(name="url_screenshot_sandbox")
    async def url_screenshot_sandbox_tool(
        url: str,
        max_bytes: int = 65536,
        case_id: str = "",
        confirm: bool = False,
    ) -> dict[str, Any]:
        """Lab-gated URL fetch + screenshot (soft-fails without Playwright). Optional case note."""
        return await url_screenshot_sandbox(
            settings,
            client,
            url=url,
            max_bytes=max_bytes,
            case_id=case_id,
            confirm=confirm,
        )
