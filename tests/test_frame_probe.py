"""Tests for the embedded-site-popup frameability probe.

The embedded gallery popup needs to know, before rendering a live iframe,
whether a site's own security headers will block framing — this is what lets
the popup show a graceful "can't embed" message instead of a silent blank
frame. These tests cover the header inspection logic, the SSRF gate that runs
before any outbound request, and the streaming behaviour that keeps a
user-supplied URL from being read into memory unbounded.

They drive a real httpx.MockTransport rather than mocking the client, so the
streaming code path itself is exercised.
"""

from __future__ import annotations

import asyncio
from unittest.mock import patch

import httpx
import pytest

from black_onyx.gallery.frame_probe import _blocks_framing, probe_frameable

SELF_ORIGIN = "https://tip.corp.example"


def _transport_client(handler):
    """Patch AsyncClient so it keeps all real behaviour (including streaming)
    but routes requests through a MockTransport."""
    transport = httpx.MockTransport(handler)

    class PatchedClient(httpx.AsyncClient):
        def __init__(self, *args, **kwargs):
            kwargs["transport"] = transport
            super().__init__(*args, **kwargs)

    return patch("black_onyx.gallery.frame_probe.httpx.AsyncClient", PatchedClient)


def _responder(headers=None, status_code=200, body=b""):
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(status_code, headers=headers or {}, content=body)
    return handler


def _public_dns():
    return patch(
        "black_onyx.favicon_fetcher.socket.getaddrinfo",
        return_value=[(2, 1, 6, "", ("93.184.216.34", 0))],
    )


class TestBlocksFraming:
    """Header semantics, isolated from any I/O."""

    def test_no_headers_is_frameable(self):
        assert _blocks_framing(httpx.Headers({}), SELF_ORIGIN) is None

    @pytest.mark.parametrize("value", ["DENY", "SAMEORIGIN", "deny", "sameorigin"])
    def test_x_frame_options_blocks(self, value):
        reason = _blocks_framing(httpx.Headers({"x-frame-options": value}), SELF_ORIGIN)
        assert reason and "X-Frame-Options" in reason

    def test_frame_ancestors_none_blocks(self):
        headers = httpx.Headers({"content-security-policy": "frame-ancestors 'none'"})
        assert _blocks_framing(headers, SELF_ORIGIN) is not None

    def test_frame_ancestors_allowlist_without_us_blocks(self):
        """Regression: an allowlist that simply doesn't name us blocks framing
        just as surely as 'none' does. Treating it as frameable put the origin
        into our CSP frame-src and rendered a blank iframe — precisely the
        failure the graceful fallback exists to prevent — and this shape
        ('self' plus an SSO host) is the common one on enterprise consoles."""
        headers = httpx.Headers(
            {"content-security-policy": "default-src 'self'; frame-ancestors 'self' https://sso.corp.example"},
        )
        reason = _blocks_framing(headers, SELF_ORIGIN)
        assert reason and "does not allow" in reason

    def test_frame_ancestors_naming_us_is_frameable(self):
        headers = httpx.Headers(
            {"content-security-policy": f"frame-ancestors 'self' {SELF_ORIGIN}"},
        )
        assert _blocks_framing(headers, SELF_ORIGIN) is None

    def test_frame_ancestors_wildcard_is_frameable(self):
        headers = httpx.Headers({"content-security-policy": "frame-ancestors *"})
        assert _blocks_framing(headers, SELF_ORIGIN) is None

    def test_csp_without_frame_ancestors_is_frameable(self):
        """frame-ancestors does not inherit from default-src."""
        headers = httpx.Headers({"content-security-policy": "default-src 'self'; script-src 'self'"})
        assert _blocks_framing(headers, SELF_ORIGIN) is None


class TestProbeFrameable:
    def test_frameable_when_no_blocking_headers(self):
        with _public_dns(), _transport_client(_responder()):
            result = asyncio.run(probe_frameable("https://example.com", SELF_ORIGIN))
        assert result == {"frameable": True, "error": None}

    def test_blocked_by_x_frame_options(self):
        with _public_dns(), _transport_client(_responder({"x-frame-options": "DENY"})):
            result = asyncio.run(probe_frameable("https://example.com", SELF_ORIGIN))
        assert result["frameable"] is False
        assert "X-Frame-Options" in result["error"]

    def test_blocked_by_redirect(self):
        with _public_dns(), _transport_client(
            _responder({"location": "https://elsewhere.example"}, status_code=302),
        ):
            result = asyncio.run(probe_frameable("https://example.com", SELF_ORIGIN))
        assert result["frameable"] is False
        assert "redirect" in result["error"]

    def test_body_is_never_downloaded(self):
        """The probe only needs headers. Reading the body would be an
        unbounded in-memory read of a user-supplied URL on the request path —
        every other outbound fetch in this codebase caps its response, so this
        one avoids the body entirely by streaming and never iterating it."""
        streamed = {"body_read": False}

        def handler(_request: httpx.Request) -> httpx.Response:
            async def gen():
                streamed["body_read"] = True
                yield b"x" * 10_000_000
            return httpx.Response(200, headers={}, content=gen())

        with _public_dns(), _transport_client(handler):
            result = asyncio.run(probe_frameable("https://example.com", SELF_ORIGIN))
        assert result["frameable"] is True
        assert streamed["body_read"] is False, "probe consumed the response body"

    def test_non_public_address_is_rejected_without_a_request(self):
        requested = {"called": False}

        def handler(_request: httpx.Request) -> httpx.Response:
            requested["called"] = True
            return httpx.Response(200)

        with patch(
            "black_onyx.favicon_fetcher.socket.getaddrinfo",
            return_value=[(2, 1, 6, "", ("127.0.0.1", 0))],
        ), _transport_client(handler):
            result = asyncio.run(probe_frameable("https://internal.example", SELF_ORIGIN))
        assert result["frameable"] is False
        assert "public address" in result["error"]
        assert requested["called"] is False

    def test_invalid_url_is_rejected(self):
        result = asyncio.run(probe_frameable("not-a-url", SELF_ORIGIN))
        assert result == {"frameable": False, "error": "Invalid URL"}

    def test_transport_error_is_reported_not_raised(self):
        def handler(_request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("boom")

        with _public_dns(), _transport_client(handler):
            result = asyncio.run(probe_frameable("https://example.com", SELF_ORIGIN))
        assert result["frameable"] is False
        assert "Request failed" in result["error"]
