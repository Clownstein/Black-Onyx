"""Encrypted, administrator-managed runtime configuration."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any

from cryptography.fernet import InvalidToken

from black_onyx.auth.database import StateDatabase
from black_onyx.config import SecurityConfig
from black_onyx.crypto import derive_fernet


SETTINGS_ID = "application"


class RuntimeSettingsStore:
    """Persist safe overrides and write-only secrets in the canonical state DB."""

    def __init__(self, database: StateDatabase, security: SecurityConfig) -> None:
        self.database = database
        from black_onyx.crypto import resolve_auth_secret

        raw_secret = resolve_auth_secret(security.auth_secret_env)
        self._fernet = derive_fernet(raw_secret, "runtime-settings")

    def load(self) -> tuple[dict[str, Any], dict[str, str]]:
        row = self.database._conn.execute(
            "SELECT config_json,secrets_encrypted FROM runtime_settings WHERE settings_id=?",
            (SETTINGS_ID,),
        ).fetchone()
        if not row:
            return {}, {}
        config = json.loads(row["config_json"] or "{}")
        secrets: dict[str, str] = {}
        if row["secrets_encrypted"]:
            try:
                decrypted = self._fernet.decrypt(row["secrets_encrypted"].encode()).decode()
                secrets = json.loads(decrypted)
            except (InvalidToken, ValueError, json.JSONDecodeError) as exc:
                raise RuntimeError("Stored runtime secrets cannot be decrypted") from exc
        return config, secrets

    def save(
        self,
        config: dict[str, Any],
        secret_updates: dict[str, str | None],
        actor_user_id: str,
    ) -> dict[str, str]:
        _, secrets = self.load()
        for name, value in secret_updates.items():
            if value is None:
                continue
            if value == "":
                secrets.pop(name, None)
            else:
                secrets[name] = value
        encrypted = self._fernet.encrypt(
            json.dumps(secrets, separators=(",", ":"), sort_keys=True).encode()
        ).decode()
        now = datetime.now(timezone.utc).isoformat()
        with self.database.transaction() as db:
            db.execute(
                """INSERT INTO runtime_settings(
                       settings_id,config_json,secrets_encrypted,updated_by,updated_at
                   ) VALUES(?,?,?,?,?)
                   ON CONFLICT(settings_id) DO UPDATE SET
                       config_json=excluded.config_json,
                       secrets_encrypted=excluded.secrets_encrypted,
                       updated_by=excluded.updated_by,
                       updated_at=excluded.updated_at""",
                (SETTINGS_ID, json.dumps(config, separators=(",", ":"), sort_keys=True), encrypted, actor_user_id, now),
            )
            db.execute(
                """INSERT INTO audit_events(
                       event_id,actor_user_id,action,target_type,target_id,detail,created_at
                   ) VALUES(?,?,?,?,?,?,?)""",
                (
                    os.urandom(16).hex(), actor_user_id, "settings.update", "runtime_settings",
                    SETTINGS_ID, json.dumps({"sections": sorted(config)}), now,
                ),
            )
        return secrets


def deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    result = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def apply_secret_environment(settings: Any, secrets: dict[str, str], deployment_environment: dict[str, str | None] | None = None) -> None:
    mappings = {
        "openai_api_key": settings.llm.openai.api_key_env,
        "claude_api_key": settings.llm.claude.api_key_env,
        "gemini_api_key": settings.llm.gemini.api_key_env,
        "firecrawl_api_key": getattr(settings.web_search, "firecrawl_api_key_env", "FIRECRAWL_API_KEY"),
        "virustotal_api_key": "VIRUSTOTAL_API_KEY",
        "abuseipdb_api_key": "ABUSEIPDB_API_KEY",
        "shodan_api_key": "SHODAN_API_KEY",
        "otx_api_key": "OTX_API_KEY",
        "misp_api_key": "MISP_API_KEY",
    }
    for stored_name, env_name in mappings.items():
        value = secrets.get(stored_name)
        if value:
            os.environ[env_name] = value
        elif deployment_environment is not None:
            original = deployment_environment.get(env_name)
            if original is None:
                os.environ.pop(env_name, None)
            else:
                os.environ[env_name] = original
    if secrets.get("qdrant_api_key"):
        from pydantic import SecretStr
        settings.qdrant.api_key = SecretStr(secrets["qdrant_api_key"])
