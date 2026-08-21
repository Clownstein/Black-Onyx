"""Firecrawl HTTP client for page scraping."""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from typing import Any

logger = logging.getLogger(__name__)

FIRECRAWL_API = "https://api.firecrawl.dev/v1/scrape"


def scrape_url(
    url: str,
    api_key: str,
    *,
    timeout: float = 60.0,
) -> dict[str, Any]:
    """Scrape a URL via Firecrawl and return markdown/text content."""
    if not api_key:
        raise RuntimeError("Firecrawl API key is not configured")

    body = json.dumps({
        "url": url,
        "formats": ["markdown"],
        "onlyMainContent": True,
    }).encode("utf-8")
    req = urllib.request.Request(
        FIRECRAWL_API,
        data=body,
        method="POST",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "User-Agent": "BlackOnyx/1.0",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as exc:
        err_body = exc.read().decode("utf-8", errors="replace")[:400]
        raise RuntimeError(f"Firecrawl HTTP {exc.code}: {err_body}") from exc
    except Exception as exc:
        raise RuntimeError(f"Firecrawl request failed: {exc}") from exc

    data = payload.get("data") or payload
    markdown = (
        data.get("markdown")
        or data.get("content")
        or ((data.get("metadata") or {}).get("description"))
        or ""
    )
    title = ((data.get("metadata") or {}).get("title") or "").strip() or url
    return {
        "url": url,
        "title": title,
        "markdown": str(markdown).strip(),
        "raw": data,
    }
