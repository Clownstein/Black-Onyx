"""Secure invite-only authentication service."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import smtplib
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from enum import Enum
from typing import Any

import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.fernet import Fernet

from black_onyx.auth.database import StateDatabase
from black_onyx.config import SecurityConfig


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(value: datetime) -> str:
    return value.isoformat()


class Role(str, Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


@dataclass(frozen=True)
class Principal:
    user_id: str
    email: str
    display_name: str
    role: Role

    def to_dict(self) -> dict[str, str]:
        return {
            "user_id": self.user_id, "email": self.email,
            "display_name": self.display_name, "role": self.role.value,
        }


class AuthError(ValueError):
    pass


class AuthService:
    password_hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)

    def __init__(self, db: StateDatabase, config: SecurityConfig) -> None:
        self.db = db
        self.config = config
        from black_onyx.crypto import resolve_auth_secret

        raw_secret = resolve_auth_secret(config.auth_secret_env)
        digest = hashlib.sha256(raw_secret.encode()).digest()
        self._fernet = Fernet(base64.urlsafe_b64encode(digest))
        self._pepper = digest
        self._attempts: dict[str, list[datetime]] = {}

    def _token_hash(self, token: str) -> str:
        return hashlib.sha256(self._pepper + token.encode()).hexdigest()

    @staticmethod
    def validate_password(password: str) -> None:
        if not 12 <= len(password) <= 128:
            raise AuthError("Password must be between 12 and 128 characters")
        common = {"password1234", "administrator", "letmein123456", "qwerty123456"}
        if password.casefold() in common:
            raise AuthError("Choose a less common password")

    def user_count(self) -> int:
        return int(self.db._conn.execute("SELECT COUNT(*) FROM users").fetchone()[0])

    def bootstrap_admin(self, email: str, password: str, display_name: str = "Administrator") -> Principal:
        if self.user_count():
            raise AuthError("Bootstrap is disabled after the first account is created")
        principal = self._create_user(email, password, display_name, Role.ADMIN)
        try:
            from black_onyx.auth.legacy_migration import migrate_legacy_state
            migrate_legacy_state(self.db, principal.user_id)
        except Exception:
            with self.db.transaction() as db:
                db.execute("DELETE FROM users WHERE user_id=?", (principal.user_id,))
            raise
        return principal

    def _insert_user(
        self, db: sqlite3.Connection, email: str, password: str, display_name: str, role: Role
    ) -> Principal:
        self.validate_password(password)
        now = iso(utcnow())
        user_id = str(uuid.uuid4())
        normalized = email.strip().casefold()
        display_name = display_name.strip()
        if not display_name:
            raise AuthError("Display name is required")
        db.execute(
            "INSERT INTO users(user_id,email,display_name,password_hash,role,created_at,updated_at) "
            "VALUES(?,?,?,?,?,?,?)",
            (user_id, normalized, display_name, self.password_hasher.hash(password), role.value, now, now),
        )
        return Principal(user_id, normalized, display_name, role)

    def _create_user(self, email: str, password: str, display_name: str, role: Role) -> Principal:
        with self.db.transaction() as db:
            try:
                return self._insert_user(db, email, password, display_name, role)
            except sqlite3.IntegrityError as exc:
                raise AuthError("An account with that email already exists") from exc

    def create_invitation(self, actor: Principal, email: str, role: Role, hours: int = 24) -> str:
        if actor.role is not Role.ADMIN:
            raise AuthError("Administrator role required")
        token = secrets.token_urlsafe(32)
        now = utcnow()
        with self.db.transaction() as db:
            db.execute(
                "INSERT INTO invitations VALUES(?,?,?,?,?,?,?,NULL)",
                (str(uuid.uuid4()), self._token_hash(token), email.strip().casefold(), role.value,
                 actor.user_id, iso(now), iso(now + timedelta(hours=hours))),
            )
        self.audit(actor, "invitation.create", "user", email)
        return token

    def register(self, token: str, password: str, display_name: str) -> Principal:
        now = utcnow()
        with self.db.transaction() as db:
            invitation = db.execute(
                "SELECT * FROM invitations WHERE token_hash=? AND used_at IS NULL",
                (self._token_hash(token),),
            ).fetchone()
            if not invitation or datetime.fromisoformat(invitation["expires_at"]) <= now:
                raise AuthError("Invitation is invalid or expired")
            try:
                principal = self._insert_user(
                    db, invitation["email"], password, display_name, Role(invitation["role"])
                )
            except sqlite3.IntegrityError as exc:
                raise AuthError("An account with that email already exists") from exc
            db.execute("UPDATE invitations SET used_at=? WHERE invitation_id=?",
                       (iso(now), invitation["invitation_id"]))
        return principal

    def create_password_reset(self, user_id: str, minutes: int = 30) -> str:
        token = secrets.token_urlsafe(32)
        now = utcnow()
        with self.db.transaction() as db:
            db.execute("DELETE FROM password_resets WHERE user_id=? AND used_at IS NULL", (user_id,))
            db.execute(
                "INSERT INTO password_resets VALUES(?,?,?,?,?,NULL)",
                (str(uuid.uuid4()), self._token_hash(token), user_id, iso(now),
                 iso(now + timedelta(minutes=minutes))),
            )
        return token

    def request_password_reset(self, email: str, ip: str = "") -> tuple[str | None, str | None]:
        now = utcnow()
        throttle_key = f"reset:{email.strip().casefold()}:{ip}"
        recent = [t for t in self._attempts.get(throttle_key, []) if now - t < timedelta(hours=1)]
        if len(recent) >= 5:
            return None, None
        recent.append(now)
        self._attempts[throttle_key] = recent
        row = self.db._conn.execute(
            "SELECT user_id,email FROM users WHERE email=? COLLATE NOCASE AND active=1",
            (email.strip().casefold(),),
        ).fetchone()
        if not row:
            return None, None
        return self.create_password_reset(row["user_id"]), row["email"]

    def reset_password(self, token: str, new_password: str) -> Principal:
        self.validate_password(new_password)
        now = utcnow()
        with self.db.transaction() as db:
            reset = db.execute(
                "SELECT r.*,u.email,u.display_name,u.role,u.active FROM password_resets r "
                "JOIN users u ON u.user_id=r.user_id "
                "WHERE r.token_hash=? AND r.used_at IS NULL",
                (self._token_hash(token),),
            ).fetchone()
            if not reset or not reset["active"] or datetime.fromisoformat(reset["expires_at"]) <= now:
                raise AuthError("Reset link is invalid or expired")
            db.execute(
                "UPDATE users SET password_hash=?,updated_at=? WHERE user_id=?",
                (self.password_hasher.hash(new_password), iso(now), reset["user_id"]),
            )
            db.execute("UPDATE password_resets SET used_at=? WHERE reset_id=?",
                       (iso(now), reset["reset_id"]))
            db.execute("DELETE FROM auth_sessions WHERE user_id=?", (reset["user_id"],))
        return Principal(reset["user_id"], reset["email"], reset["display_name"], Role(reset["role"]))

    def change_password(self, principal: Principal, current_password: str, new_password: str) -> None:
        row = self.db._conn.execute(
            "SELECT password_hash FROM users WHERE user_id=? AND active=1", (principal.user_id,)
        ).fetchone()
        try:
            if not row:
                raise VerifyMismatchError
            self.password_hasher.verify(row["password_hash"], current_password)
        except VerifyMismatchError:
            raise AuthError("Invalid credentials")
        self.validate_password(new_password)
        with self.db.transaction() as db:
            db.execute(
                "UPDATE users SET password_hash=?,updated_at=? WHERE user_id=?",
                (self.password_hasher.hash(new_password), iso(utcnow()), principal.user_id),
            )
            db.execute("DELETE FROM auth_sessions WHERE user_id=?", (principal.user_id,))

    def update_user(self, actor: Principal, user_id: str, role: Role | None, active: bool | None) -> None:
        if actor.role is not Role.ADMIN:
            raise AuthError("Administrator role required")
        row = self.db._conn.execute("SELECT role,active FROM users WHERE user_id=?", (user_id,)).fetchone()
        if not row:
            raise AuthError("User not found")
        next_role = role.value if role is not None else row["role"]
        next_active = int(active) if active is not None else int(row["active"])
        if row["role"] == Role.ADMIN.value and (next_role != Role.ADMIN.value or not next_active):
            admins = self.db._conn.execute(
                "SELECT COUNT(*) FROM users WHERE role='admin' AND active=1"
            ).fetchone()[0]
            if admins <= 1:
                raise AuthError("The last active administrator cannot be disabled or demoted")
        with self.db.transaction() as db:
            db.execute(
                "UPDATE users SET role=?,active=?,updated_at=? WHERE user_id=?",
                (next_role, next_active, iso(utcnow()), user_id),
            )
            if not next_active or next_role != row["role"]:
                db.execute("DELETE FROM auth_sessions WHERE user_id=?", (user_id,))
        self.audit(actor, "user.update", "user", user_id, detail={"role": next_role, "active": bool(next_active)})

    def disable_mfa(self, principal: Principal, password: str, code: str) -> None:
        self.authenticate(principal.email, password, code)
        with self.db.transaction() as db:
            db.execute(
                "UPDATE users SET mfa_enabled=0,mfa_secret_encrypted=NULL,updated_at=? WHERE user_id=?",
                (iso(utcnow()), principal.user_id),
            )
            db.execute("DELETE FROM recovery_codes WHERE user_id=?", (principal.user_id,))

    def authenticate(
        self, email: str, password: str, mfa_code: str | None = None, ip: str = ""
    ) -> Principal:
        email_key = email.strip().casefold()
        key = f"login:{email_key}:{ip}"
        now = utcnow()
        recent = [t for t in self._attempts.get(key, []) if now - t < timedelta(minutes=15)]
        if len(recent) >= 8:
            raise AuthError("Too many login attempts; try again later")
        row = self.db._conn.execute(
            "SELECT * FROM users WHERE email=? COLLATE NOCASE", (email_key,)
        ).fetchone()
        try:
            if not row or not row["active"]:
                raise VerifyMismatchError
            self.password_hasher.verify(row["password_hash"], password)
            if row["mfa_enabled"]:
                if not mfa_code or not self.verify_mfa(row["user_id"], mfa_code):
                    raise AuthError("MFA code required or invalid")
        except VerifyMismatchError:
            recent.append(now)
            self._attempts[key] = recent
            raise AuthError("Invalid credentials")
        self._attempts.pop(key, None)
        return Principal(row["user_id"], row["email"], row["display_name"], Role(row["role"]))

    def create_session(self, principal: Principal, ip: str = "", user_agent: str = "") -> tuple[str, str]:
        session = secrets.token_urlsafe(48)
        csrf = secrets.token_urlsafe(32)
        now = utcnow()
        with self.db.transaction() as db:
            db.execute(
                "INSERT INTO auth_sessions VALUES(?,?,?,?,?,?,?,?)",
                (self._token_hash(session), principal.user_id, self._token_hash(csrf), iso(now), iso(now),
                 iso(now + timedelta(hours=self.config.session_absolute_hours)), ip, user_agent[:500]),
            )
        return session, csrf

    def principal_for_session(self, session: str) -> tuple[Principal, str] | None:
        now = utcnow()
        row = self.db._conn.execute(
            "SELECT s.*,u.email,u.display_name,u.role,u.active FROM auth_sessions s "
            "JOIN users u ON u.user_id=s.user_id WHERE s.session_hash=?",
            (self._token_hash(session),),
        ).fetchone()
        if not row or not row["active"]:
            return None
        last_seen = datetime.fromisoformat(row["last_seen_at"])
        if datetime.fromisoformat(row["expires_at"]) <= now or now - last_seen > timedelta(minutes=self.config.session_idle_minutes):
            self.delete_session(session)
            return None
        with self.db.transaction() as db:
            db.execute("UPDATE auth_sessions SET last_seen_at=? WHERE session_hash=?",
                       (iso(now), self._token_hash(session)))
        principal = Principal(row["user_id"], row["email"], row["display_name"], Role(row["role"]))
        return principal, row["csrf_hash"]

    def principal_for_mcp_service_key(self, provided_key: str) -> Principal | None:
        """Resolve a machine Principal for MCP when ``X-MCP-Service-Key`` matches.

        Fail-closed: both ``BLACK_ONYX_MCP_SERVICE_KEY`` and
        ``BLACK_ONYX_MCP_ACTOR_USER_ID`` must be set; the actor must be an active
        ``admin`` or ``analyst``. Demo-shaped keys require ``ALLOW_DEMO_KEYS``.
        """
        expected = (os.environ.get("BLACK_ONYX_MCP_SERVICE_KEY") or "").strip()
        actor_id = (os.environ.get("BLACK_ONYX_MCP_ACTOR_USER_ID") or "").strip()
        supplied = (provided_key or "").strip()
        if not expected or not actor_id or not supplied:
            return None
        if not secrets.compare_digest(supplied, expected):
            return None
        if self._is_demo_shaped_key(expected) and not self._allow_demo_keys():
            return None
        row = self.db._conn.execute(
            "SELECT user_id,email,display_name,role,active FROM users WHERE user_id=?",
            (actor_id,),
        ).fetchone()
        if not row or not row["active"]:
            return None
        role = Role(row["role"])
        if role not in {Role.ADMIN, Role.ANALYST}:
            return None
        return Principal(row["user_id"], row["email"], row["display_name"], role)

    @staticmethod
    def _allow_demo_keys() -> bool:
        return (os.environ.get("ALLOW_DEMO_KEYS") or "").strip().lower() in {
            "1", "true", "yes", "on",
        }

    @staticmethod
    def _is_demo_shaped_key(value: str) -> bool:
        v = (value or "").strip().lower()
        if not v:
            return False
        return any(v.startswith(p) or v == p for p in ("dev-", "demo-", "changeme", "minioadmin"))

    def verify_csrf(self, expected_hash: str, supplied: str) -> bool:
        return secrets.compare_digest(expected_hash, self._token_hash(supplied))

    def delete_session(self, session: str) -> None:
        with self.db.transaction() as db:
            db.execute("DELETE FROM auth_sessions WHERE session_hash=?", (self._token_hash(session),))

    def begin_mfa(self, principal: Principal) -> str:
        secret = pyotp.random_base32()
        encrypted = self._fernet.encrypt(secret.encode()).decode()
        with self.db.transaction() as db:
            db.execute("UPDATE users SET mfa_secret_encrypted=?,mfa_enabled=0 WHERE user_id=?",
                       (encrypted, principal.user_id))
        return pyotp.TOTP(secret).provisioning_uri(name=principal.email, issuer_name="Black Onyx")

    def enable_mfa(self, principal: Principal, code: str) -> list[str]:
        if not self.verify_mfa(principal.user_id, code, allow_disabled=True):
            raise AuthError("Invalid TOTP code")
        codes = [secrets.token_hex(5) for _ in range(10)]
        with self.db.transaction() as db:
            db.execute("UPDATE users SET mfa_enabled=1 WHERE user_id=?", (principal.user_id,))
            db.execute("DELETE FROM recovery_codes WHERE user_id=?", (principal.user_id,))
            db.executemany("INSERT INTO recovery_codes(user_id,code_hash) VALUES(?,?)",
                           [(principal.user_id, self._token_hash(c)) for c in codes])
        return codes

    def verify_mfa(self, user_id: str, code: str, allow_disabled: bool = False) -> bool:
        row = self.db._conn.execute(
            "SELECT mfa_secret_encrypted,mfa_enabled FROM users WHERE user_id=?", (user_id,)
        ).fetchone()
        if not row or not row["mfa_secret_encrypted"] or (not row["mfa_enabled"] and not allow_disabled):
            return False
        secret = self._fernet.decrypt(row["mfa_secret_encrypted"].encode()).decode()
        if pyotp.TOTP(secret).verify(code, valid_window=1):
            return True
        code_hash = self._token_hash(code)
        recovery = self.db._conn.execute(
            "SELECT 1 FROM recovery_codes WHERE user_id=? AND code_hash=? AND used_at IS NULL",
            (user_id, code_hash),
        ).fetchone()
        if recovery:
            with self.db.transaction() as db:
                db.execute("UPDATE recovery_codes SET used_at=? WHERE user_id=? AND code_hash=?",
                           (iso(utcnow()), user_id, code_hash))
            return True
        return False

    def audit(self, actor: Principal | None, action: str, target_type: str = "", target_id: str = "",
              ip: str = "", detail: dict[str, Any] | None = None) -> None:
        with self.db.transaction() as db:
            db.execute(
                "INSERT INTO audit_events VALUES(?,?,?,?,?,?,?,?)",
                (str(uuid.uuid4()), actor.user_id if actor else None, action, target_type, target_id,
                 ip, json.dumps(detail or {}, separators=(",", ":")), iso(utcnow())),
            )

    def send_link(self, email: str, subject: str, link: str) -> bool:
        if not self.config.smtp_host or not self.config.smtp_from:
            return False
        message = EmailMessage()
        message["From"] = self.config.smtp_from
        message["To"] = email
        message["Subject"] = subject
        message.set_content(f"Use this single-use link before it expires:\n\n{link}\n")
        username = os.environ.get(self.config.smtp_username_env)
        password = os.environ.get(self.config.smtp_password_env)
        with smtplib.SMTP(self.config.smtp_host, self.config.smtp_port, timeout=15) as smtp:
            smtp.starttls()
            if username and password:
                smtp.login(username, password)
            smtp.send_message(message)
        return True
