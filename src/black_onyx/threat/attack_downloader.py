"""Download and cache MITRE ATT&CK STIX data."""

from __future__ import annotations

import logging
import hashlib
import json
import os
from pathlib import Path

import httpx

logger = logging.getLogger(__name__)

def download_attack_data(
    data_dir: str, source_url: str, expected_sha256: str, max_bytes: int
) -> bool:
    """Download MITRE ATT&CK STIX data to local cache.

    Args:
        data_dir: Directory to store the cached JSON file.

    Returns:
        True if download succeeded, False otherwise.
    """
    if not source_url.startswith("https://") or len(expected_sha256) != 64:
        raise ValueError("ATT&CK refresh requires an HTTPS source and pinned SHA-256")
    path = Path(data_dir)
    path.mkdir(parents=True, exist_ok=True)
    cache_file = path / "mitre_attack.json"
    temp_file = path / f".mitre_attack.{os.getpid()}.tmp"
    try:
        digest = hashlib.sha256()
        total = 0
        with httpx.stream("GET", source_url, timeout=120, follow_redirects=False) as resp:
            resp.raise_for_status()
            if resp.is_redirect:
                raise ValueError("ATT&CK source redirects are not accepted")
            with temp_file.open("wb") as output:
                for chunk in resp.iter_bytes():
                    total += len(chunk)
                    if total > max_bytes:
                        raise ValueError("ATT&CK source exceeds configured size limit")
                    digest.update(chunk)
                    output.write(chunk)
        if digest.hexdigest() != expected_sha256.casefold():
            raise ValueError("ATT&CK source hash does not match configured SHA-256")
        data = json.loads(temp_file.read_text(encoding="utf-8"))
        objects = data.get("objects")
        if data.get("type") != "bundle" or not isinstance(objects, list) or not objects:
            raise ValueError("ATT&CK source is not a non-empty STIX bundle")
        temp_file.replace(cache_file)
        logger.info(f"Downloaded ATT&CK data to {cache_file}")
        return True
    except Exception as e:
        logger.error(f"Failed to download ATT&CK data: {e}")
        temp_file.unlink(missing_ok=True)
        return False
