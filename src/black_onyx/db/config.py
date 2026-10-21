"""Database URL resolution for platform Postgres stores."""

from __future__ import annotations

import os


def _truthy(value: str | None) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes", "on"}


def production_requires_postgres(*, production: bool | None = None) -> bool:
    if production is not None:
        return production
    return _truthy(os.environ.get("QDRANT_SECURITY__PRODUCTION"))


def black_onyx_database_url() -> str | None:
    url = (os.environ.get("BLACK_ONYX_DATABASE_URL") or "").strip()
    return url or None


def security_gateway_database_url() -> str | None:
    url = (os.environ.get("SECURITY_GATEWAY_DATABASE_URL") or "").strip()
    return url or None


def require_black_onyx_database_url(*, production: bool) -> str | None:
    url = black_onyx_database_url()
    if production and not url:
        raise RuntimeError(
            "BLACK_ONYX_DATABASE_URL is required in production (no SQLite fallback)"
        )
    return url
