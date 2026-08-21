"""Server-side probe for whether a user-pinned site can be embedded in an iframe.

Most SIEM/EDR/vendor consoles send `X-Frame-Options` or a CSP `frame-ancestors`
directive that blocks framing outright — the gallery's "embedded" open mode
needs to know this *before* trying to render a live iframe, so the popup can
show a graceful fallback instead of a silent blank frame.

This performs a real outbound HTTP request to a user-supplied URL, which is
the same SSRF shape `favicon_fetcher.py` already guards against for the same
sites feature (an authenticated user's server-initiated request to an address
they do not necessarily control), so it reuses that module's exact
resolves-to-public-address check rather than a third implementation of it.
Unlike the favicon fetch, this never reads a response body — only headers —
and never follows redirects (a redirect could otherwise retarget a private or
metadata address, and a redirect target isn't necessarily framed by the same
policy as the URL the user actually pinned).
"""

from __future__ import annotations

import logging
from urllib.parse import urlsplit

import httpx

from black_onyx.favicon_fetcher import _resolves_to_public_address

logger = logging.getLogger(__name__)

PROBE_TIMEOUT_SECONDS = 5.0


def _blocks_framing(headers: httpx.Headers, self_origin: str | None = None) -> str | None:
    """Return a human-readable reason the site can't be framed, or None if
    nothing in these headers blocks it.

    `self_origin` is Black Onyx's own origin — the one that would actually
    appear as the frame ancestor. A `frame-ancestors` allowlist that does not
    name it blocks us just as surely as `'none'` does, so the check has to
    compare against it rather than only special-casing `'none'`.

    Source-expression matching is intentionally conservative: anything beyond
    an exact origin match or `*` (scheme-only sources, host wildcards like
    `*.corp.example`) is reported as blocked. Being wrong in that direction
    costs the analyst a working iframe but still gives them the popup and an
    "Open in new tab" button; being wrong in the other direction renders a
    silently blank frame, which is the failure this probe exists to prevent.
    """
    xfo = (headers.get("x-frame-options") or "").strip().upper()
    if xfo in {"DENY", "SAMEORIGIN"}:
        return f"Site sends X-Frame-Options: {xfo}"
    # A CSP with no frame-ancestors directive at all does not restrict framing
    # (frame-ancestors does not inherit from default-src), so absence is
    # treated as "not blocked".
    csp = headers.get("content-security-policy") or ""
    for directive in csp.split(";"):
        parts = directive.strip().split()
        if not parts or parts[0].lower() != "frame-ancestors":
            continue
        values = {v.strip("'\" ").lower() for v in parts[1:]}
        if not values or values == {"none"}:
            return "Site's CSP frame-ancestors blocks all embedding"
        if "*" in values:
            return None
        if self_origin and self_origin.lower().rstrip("/") in values:
            return None
        # Includes the common `'self'` case: that means the target site's own
        # origin, which is by definition not ours.
        return "Site's CSP frame-ancestors does not allow this application's origin"
    return None


async def probe_frameable(url: str, self_origin: str | None = None) -> dict:
    """Probe `url` for framing-blocking headers.

    Returns {"frameable": bool, "error": str | None}. Never raises — a probe
    failure (unresolvable host, non-public address, timeout, transport error,
    a redirect) is reported as not-frameable with an explanatory message
    rather than propagated, since this always runs as a best-effort
    side-channel to a site create/update/refresh call that must otherwise
    succeed normally.
    """
    parsed = urlsplit((url or "").strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return {"frameable": False, "error": "Invalid URL"}
    if not _resolves_to_public_address(parsed.hostname):
        # Matches the favicon fetcher's stance exactly: sites that resolve
        # privately (including the same-machine dev exception site creation
        # itself allows) are not auto-probed, since the probe request would
        # otherwise be the server making an SSRF-shaped call to an address it
        # does not control. The popup still opens for these — as an
        # unverified fallback, not a live embed.
        return {"frameable": False, "error": "Site does not resolve to a public address"}

    try:
        async with httpx.AsyncClient(
            timeout=PROBE_TIMEOUT_SECONDS, follow_redirects=False, trust_env=False,
        ) as client:
            # Streamed so only the response *headers* are read — the body is
            # never downloaded. A plain client.get() buffers the whole body
            # into memory, which for a user-supplied URL is an unbounded read
            # on the request path; every other outbound fetch in this codebase
            # (favicon_fetcher, feed_manager, generic_rest) caps its response,
            # and this one has nothing it needs from the body at all.
            async with client.stream("GET", url) as response:
                is_redirect = response.is_redirect
                headers = response.headers
    except httpx.HTTPError as exc:
        return {"frameable": False, "error": f"Request failed: {exc}"}

    if is_redirect:
        return {"frameable": False, "error": "Site responded with a redirect"}

    reason = _blocks_framing(headers, self_origin)
    if reason:
        return {"frameable": False, "error": reason}
    return {"frameable": True, "error": None}
