from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

import httpx

# Security response headers a webapp surface is expected to set.
SECURITY_HEADERS = (
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
)


def probe_url(url: str, *, client: httpx.Client, timeout: float = 5.0) -> dict[str, Any]:
    """Soft-probe a webapp surface target for TLS + security headers.

    Never raises: transport/timeout errors are captured in the result so the
    evaluation loop keeps running for other targets.
    """
    parsed = urlparse(url)
    tls = parsed.scheme == "https"
    result: dict[str, Any] = {
        "url": url,
        "tls": tls,
        "reachable": False,
        "status_code": None,
        "present_security_headers": [],
        "missing_security_headers": list(SECURITY_HEADERS),
        "error": None,
    }
    try:
        response = client.get(url, timeout=timeout, follow_redirects=True)
    except httpx.HTTPError as exc:
        result["error"] = str(exc)
        return result

    headers = {k.lower(): v for k, v in response.headers.items()}
    present = [h for h in SECURITY_HEADERS if h in headers]
    missing = [h for h in SECURITY_HEADERS if h not in headers]
    result.update(
        {
            "reachable": True,
            "status_code": response.status_code,
            "present_security_headers": present,
            "missing_security_headers": missing,
        }
    )
    return result


def probe_targets(
    urls: list[str], *, client: httpx.Client, timeout: float = 5.0
) -> list[dict[str, Any]]:
    return [probe_url(u, client=client, timeout=timeout) for u in urls]
