"""Encrypted storage for user-saved third-party site logins.

Saved logins must be recoverable in plaintext (the user needs them back to
log into the external site), so — per OWASP guidance — they are encrypted,
not hashed, the same way AuthService encrypts MFA secrets and
RuntimeSettingsStore encrypts admin secrets. The Fernet key is derived from
the same server-held BLACK_ONYX_AUTH_SECRET (or legacy DEFENDERS_CHAT_AUTH_SECRET)
via derive_fernet with a domain suffix unique to this subsystem, so a leaked key
here cannot decrypt MFA secrets or runtime settings, and vice versa.

There is no user-supplied vault passphrase / KDF: "LOCKED" is a client-side
UI affordance, not a server-enforced unlock gate. Access control is the
normal authenticated session plus per-site-per-user rate limiting and a full
audit trail on every reveal attempt (including throttled ones).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken

from black_onyx.auth.database import StateDatabase
from black_onyx.config import SecurityConfig
from black_onyx.crypto import derive_fernet
from black_onyx.rate_limit import SlidingWindowLimiter

REVEAL_MAX_ATTEMPTS = 10
REVEAL_WINDOW = timedelta(minutes=15)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class SiteCredentialError(ValueError):
    pass


class SiteCredentialRateLimited(SiteCredentialError):
    pass


class SiteCredentialStore:
    def __init__(self, database: StateDatabase, security: SecurityConfig) -> None:
        self.database = database
        from black_onyx.crypto import resolve_auth_secret

        raw_secret = resolve_auth_secret(security.auth_secret_env)
        self._fernet: Fernet = derive_fernet(raw_secret, "site-credentials")
        self._reveal_limiter = SlidingWindowLimiter()

    def create_or_rotate(
        self, owner_user_id: str, site_id: str, username: str, secret: str, notes: Optional[str],
    ) -> tuple[str, bool]:
        """Create or rotate the single credential for a site.

        Returns (credential_id, rotated) where rotated is True if a prior
        credential for this site already existed.
        """
        now = _now_iso()
        username_encrypted = self._fernet.encrypt(username.encode()).decode()
        secret_encrypted = self._fernet.encrypt(secret.encode()).decode()
        notes_encrypted = self._fernet.encrypt(notes.encode()).decode() if notes else None
        with self.database.transaction() as db:
            site = db.execute(
                "SELECT site_id FROM user_sites WHERE site_id=? AND owner_user_id=?",
                (site_id, owner_user_id),
            ).fetchone()
            if not site:
                raise SiteCredentialError("Site not found")
            existing = db.execute(
                "SELECT credential_id FROM stored_credentials WHERE site_id=?", (site_id,),
            ).fetchone()
            rotated = bool(existing)
            credential_id = existing["credential_id"] if existing else str(uuid.uuid4())
            if existing:
                db.execute(
                    "UPDATE stored_credentials SET username_encrypted=?,secret_encrypted=?,"
                    "notes_encrypted=?,updated_at=? WHERE credential_id=?",
                    (username_encrypted, secret_encrypted, notes_encrypted, now, credential_id),
                )
            else:
                db.execute(
                    "INSERT INTO stored_credentials("
                    "credential_id,owner_user_id,site_id,username_encrypted,secret_encrypted,"
                    "notes_encrypted,created_at,updated_at,last_accessed_at) "
                    "VALUES(?,?,?,?,?,?,?,?,NULL)",
                    (credential_id, owner_user_id, site_id, username_encrypted, secret_encrypted,
                     notes_encrypted, now, now),
                )
            db.execute(
                "UPDATE user_sites SET credential_id=?,updated_at=? WHERE site_id=?",
                (credential_id, now, site_id),
            )
        return credential_id, rotated

    def reveal(self, owner_user_id: str, site_id: str) -> dict[str, Optional[str]]:
        """Decrypt and return the saved login for a site, subject to a
        per-user-per-site sliding-window rate limit. Callers must audit both
        the allowed and rate-limited outcomes."""
        limiter_key = f"site_credential:{owner_user_id}:{site_id}"
        if not self._reveal_limiter.check(limiter_key, REVEAL_MAX_ATTEMPTS, REVEAL_WINDOW):
            raise SiteCredentialRateLimited("Too many reveal attempts; try again later")
        row = self.database._conn.execute(
            "SELECT * FROM stored_credentials WHERE site_id=? AND owner_user_id=?",
            (site_id, owner_user_id),
        ).fetchone()
        if not row:
            raise SiteCredentialError("No saved login for this site")
        try:
            username = self._fernet.decrypt(row["username_encrypted"].encode()).decode()
            secret = self._fernet.decrypt(row["secret_encrypted"].encode()).decode()
            notes = (
                self._fernet.decrypt(row["notes_encrypted"].encode()).decode()
                if row["notes_encrypted"] else None
            )
        except InvalidToken as exc:
            raise SiteCredentialError("Stored credential cannot be decrypted") from exc
        now = _now_iso()
        with self.database.transaction() as db:
            db.execute(
                "UPDATE stored_credentials SET last_accessed_at=? WHERE credential_id=?",
                (now, row["credential_id"]),
            )
        return {
            "username": username,
            "secret": secret,
            "notes": notes,
            "updated_at": row["updated_at"],
            "last_accessed_at": now,
        }

    def delete(self, owner_user_id: str, site_id: str) -> bool:
        with self.database.transaction() as db:
            row = db.execute(
                "SELECT credential_id FROM stored_credentials WHERE site_id=? AND owner_user_id=?",
                (site_id, owner_user_id),
            ).fetchone()
            if not row:
                return False
            db.execute("DELETE FROM stored_credentials WHERE credential_id=?", (row["credential_id"],))
            db.execute(
                "UPDATE user_sites SET credential_id=NULL,updated_at=? WHERE site_id=?",
                (_now_iso(), site_id),
            )
        return True
