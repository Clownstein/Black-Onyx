"""SearXNG HTTP client for web result discovery."""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

logger = logging.getLogger(__name__)


def searxng_reachable(base_url: str, timeout: float = 3.0) -> bool:
    """Return True when SearXNG answers a lightweight request."""
    url = base_url.rstrip("/") + "/"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "BlackOnyx/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return 200 <= response.status < 500
    except Exception:
        return False


def search(
    base_url: str,
    query: str,
    *,
    max_results: int = 5,
    timeout: float = 30.0,
) -> list[dict[str, Any]]:
    """Run a SearXNG JSON search and return normalized result dicts."""
    params = urllib.parse.urlencode({
        "q": query,
        "format": "json",
        "language": "en",
    })
    url = f"{base_url.rstrip('/')}/search?{params}"
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "BlackOnyx/1.0", "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")[:300]
        raise RuntimeError(f"SearXNG HTTP {exc.code}: {body}") from exc
    except Exception as exc:
        raise RuntimeError(f"SearXNG request failed: {exc}") from exc

    results: list[dict[str, Any]] = []
    for item in payload.get("results") or []:
        link = (item.get("url") or "").strip()
        if not link:
            continue
        results.append({
            "title": (item.get("title") or "").strip() or link,
            "url": link,
            "snippet": (item.get("content") or item.get("snippet") or "").strip(),
            "engine": item.get("engine") or "",
        })
        if len(results) >= max_results:
            break
    return results
