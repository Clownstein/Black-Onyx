"""Shared authentication service lifecycle."""

from __future__ import annotations

from functools import lru_cache

from black_onyx.auth.database import StateDatabase
from black_onyx.auth.service import AuthService
from black_onyx.config import get_settings


@lru_cache(maxsize=1)
def get_auth_service() -> AuthService:
    settings = get_settings()
    return AuthService(StateDatabase(settings.storage.state_dir), settings.security)
