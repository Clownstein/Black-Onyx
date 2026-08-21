"""Check that every preset feed URL still returns a parseable RSS/Atom document.

Run with the project virtualenv: ``python scripts/check_feed_presets.py``.
"""

from __future__ import annotations

import asyncio
import sys
from xml.etree import ElementTree

import httpx

HEADERS = {
    "User-Agent": "BlackOnyx/1.0 feed-check",
    "Accept": "application/rss+xml, application/atom+xml, application/xml, text/xml, */*",
}

PRESETS = [
    ("Microsoft Security Blog", "https://www.microsoft.com/en-us/security/blog/feed/"),
    ("MSRC Security Updates", "https://api.msrc.microsoft.com/update-guide/rss"),
    ("Cisco Talos", "https://blog.talosintelligence.com/rss/"),
    ("Unit 42", "https://unit42.paloaltonetworks.com/feed/"),
    ("Google Threat Intelligence", "https://cloudblog.withgoogle.com/topics/threat-intelligence/rss/"),
    ("Check Point Research", "https://research.checkpoint.com/feed/"),
    ("Securelist", "https://securelist.com/feed/"),
    ("WeLiveSecurity", "https://www.welivesecurity.com/en/rss/feed/"),
    ("Fortinet Threat Research", "https://feeds.fortinet.com/fortinet/blog/threat-research"),
    ("Red Canary", "https://redcanary.com/feed/"),
    ("Rapid7 Blog", "https://www.rapid7.com/blog/rss/"),
    ("SANS Internet Storm Center", "https://isc.sans.edu/rssfeed.xml"),
    ("The Hacker News", "https://feeds.feedburner.com/TheHackersNews"),
    ("BleepingComputer", "https://www.bleepingcomputer.com/feed/"),
    ("Krebs on Security", "https://krebsonsecurity.com/feed/"),
    ("The Record", "https://therecord.media/feed"),
    ("Exploit-DB", "https://www.exploit-db.com/rss.xml"),
]


async def check(client: httpx.AsyncClient, name: str, url: str) -> tuple[str, str]:
    try:
        response = await client.get(url, headers=HEADERS, follow_redirects=True, timeout=25.0)
    except Exception as error:  # noqa: BLE001 - report any transport failure verbatim
        return name, f"FAIL transport: {type(error).__name__}: {error}"
    if response.status_code >= 400:
        return name, f"FAIL http {response.status_code}"
    try:
        root = ElementTree.fromstring(response.content)
    except ElementTree.ParseError as error:
        content_type = response.headers.get("content-type", "?")
        return name, f"FAIL parse ({content_type}): {error}"
    items = root.findall(".//item") or root.findall(".//{http://www.w3.org/2005/Atom}entry")
    if not items:
        return name, "FAIL no items"
    return name, f"OK {len(items)} items"


async def main() -> int:
    async with httpx.AsyncClient() as client:
        results = await asyncio.gather(*(check(client, name, url) for name, url in PRESETS))
    failures = 0
    for name, status in results:
        if status.startswith("FAIL"):
            failures += 1
        print(f"{name:32} {status}")
    print(f"\n{len(results) - failures}/{len(results)} presets healthy")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
