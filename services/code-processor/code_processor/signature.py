from __future__ import annotations

import hashlib
import hmac


def verify_github_signature(body: bytes, header: str, secret: str) -> bool:
    """Verify GitHub X-Hub-Signature-256 header using HMAC-SHA256.

    Expected header form: ``sha256=<hexdigest>``.
    """
    if not secret or not header:
        return False
    prefix = "sha256="
    if not header.startswith(prefix):
        return False
    digest = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    provided = header[len(prefix) :].strip()
    return hmac.compare_digest(digest, provided)
