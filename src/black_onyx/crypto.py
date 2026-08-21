"""Shared Fernet key derivation for encrypted-at-rest application secrets.

Each subsystem that needs reversible encryption (as opposed to password
hashing) derives its own Fernet key from the same root secret plus a unique
domain suffix, so a leaked key for one subsystem cannot decrypt another's
ciphertext. See RuntimeSettingsStore and SiteCredentialStore for consumers.
"""

from __future__ import annotations

import base64
import hashlib
import os

from cryptography.fernet import Fernet

# Preferred name first; DEFENDERS_CHAT_AUTH_SECRET remains accepted for older deploys.
_AUTH_SECRET_FALLBACKS = ("BLACK_ONYX_AUTH_SECRET", "DEFENDERS_CHAT_AUTH_SECRET")


def resolve_auth_secret(env_name: str) -> str:
    """Return the application root secret from the configured or legacy env vars."""
    seen: set[str] = set()
    for key in (env_name, *_AUTH_SECRET_FALLBACKS):
        if not key or key in seen:
            continue
        seen.add(key)
        value = os.environ.get(key, "").strip()
        if value:
            return value
    raise RuntimeError(
        f"{env_name} is required (legacy DEFENDERS_CHAT_AUTH_SECRET is also accepted)"
    )


def derive_fernet(raw_secret: str, domain: str) -> Fernet:
    """Derive a domain-separated Fernet key from the application root secret."""
    digest = hashlib.sha256(raw_secret.encode() + f":{domain}:v1".encode()).digest()
    return Fernet(base64.urlsafe_b64encode(digest))
