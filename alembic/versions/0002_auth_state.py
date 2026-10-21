"""Auth schema tables (canonical black_onyx.sqlite shape)."""

from typing import Sequence, Union

from alembic import op

revision: str = "0002"
down_revision: Union[str, None] = "0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("SET search_path TO auth")
    op.execute("""
        CREATE TABLE IF NOT EXISTS schema_version (
            version INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS users (
            user_id TEXT PRIMARY KEY,
            email TEXT NOT NULL UNIQUE,
            display_name TEXT NOT NULL DEFAULT '',
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('admin','analyst','viewer')),
            active INTEGER NOT NULL DEFAULT 1,
            mfa_secret_encrypted TEXT,
            mfa_enabled INTEGER NOT NULL DEFAULT 0,
            mfa_last_totp_step INTEGER NOT NULL DEFAULT -1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS auth_sessions (
            session_hash TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
            csrf_hash TEXT NOT NULL,
            created_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            ip_address TEXT,
            user_agent TEXT
        );
        CREATE TABLE IF NOT EXISTS invitations (
            invitation_id TEXT PRIMARY KEY,
            token_hash TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL,
            role TEXT NOT NULL,
            created_by TEXT NOT NULL REFERENCES users(user_id),
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            used_at TEXT
        );
        CREATE TABLE IF NOT EXISTS password_resets (
            reset_id TEXT PRIMARY KEY,
            token_hash TEXT NOT NULL UNIQUE,
            user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            used_at TEXT
        );
        CREATE TABLE IF NOT EXISTS recovery_codes (
            user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
            code_hash TEXT NOT NULL,
            used_at TEXT,
            PRIMARY KEY(user_id, code_hash)
        );
        CREATE TABLE IF NOT EXISTS audit_events (
            event_id TEXT PRIMARY KEY,
            actor_user_id TEXT REFERENCES users(user_id),
            action TEXT NOT NULL,
            target_type TEXT,
            target_id TEXT,
            ip_address TEXT,
            detail TEXT,
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_sessions_user ON auth_sessions(user_id);
        CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_events(created_at);
        CREATE TABLE IF NOT EXISTS jobs (
            job_id TEXT PRIMARY KEY,
            owner_user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
            job_type TEXT NOT NULL,
            status TEXT NOT NULL CHECK(status IN (
                'queued','running','stopping','stopped','completed','failed'
            )),
            detail TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            expires_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_jobs_owner_updated ON jobs(owner_user_id, updated_at DESC);
        CREATE TABLE IF NOT EXISTS legacy_migrations (
            migration_id TEXT PRIMARY KEY,
            applied_at TEXT NOT NULL,
            backup_dir TEXT NOT NULL,
            detail TEXT NOT NULL DEFAULT '{}'
        );
        CREATE TABLE IF NOT EXISTS reports (
            report_id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            format TEXT NOT NULL CHECK(format IN ('markdown','html','pdf')),
            relative_path TEXT NOT NULL,
            created_by TEXT NOT NULL REFERENCES users(user_id),
            created_at TEXT NOT NULL,
            template TEXT NOT NULL DEFAULT 'intel'
        );
        CREATE INDEX IF NOT EXISTS idx_reports_created ON reports(created_at DESC);
        CREATE TABLE IF NOT EXISTS runtime_settings (
            settings_id TEXT PRIMARY KEY,
            config_json TEXT NOT NULL DEFAULT '{}',
            secrets_encrypted TEXT,
            updated_by TEXT REFERENCES users(user_id),
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS user_sites (
            site_id TEXT PRIMARY KEY,
            owner_user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            url TEXT NOT NULL,
            login_url TEXT,
            section TEXT NOT NULL DEFAULT 'sites'
                CHECK(section IN ('investigate','intelligence','operations','control','sites')),
            tags TEXT NOT NULL DEFAULT '[]',
            open_mode TEXT NOT NULL DEFAULT 'new_tab'
                CHECK(open_mode IN ('new_tab','embedded','launcher')),
            favicon_relative_path TEXT,
            credential_id TEXT,
            frameable INTEGER,
            frameable_checked_at TEXT,
            frameable_error TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_sites_owner ON user_sites(owner_user_id, updated_at DESC);
        CREATE TABLE IF NOT EXISTS stored_credentials (
            credential_id TEXT PRIMARY KEY,
            owner_user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
            site_id TEXT NOT NULL REFERENCES user_sites(site_id) ON DELETE CASCADE,
            username_encrypted TEXT NOT NULL,
            secret_encrypted TEXT NOT NULL,
            notes_encrypted TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            last_accessed_at TEXT
        );
        CREATE UNIQUE INDEX IF NOT EXISTS idx_credentials_site ON stored_credentials(site_id);
        CREATE INDEX IF NOT EXISTS idx_credentials_owner ON stored_credentials(owner_user_id);
        CREATE TABLE IF NOT EXISTS analytics_views (
            view_id TEXT PRIMARY KEY,
            owner_user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            range_key TEXT NOT NULL DEFAULT '30d',
            tab_key TEXT NOT NULL DEFAULT 'volume',
            role_default TEXT CHECK(role_default IS NULL OR role_default IN ('admin','analyst','viewer')),
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(owner_user_id, name)
        );
        CREATE INDEX IF NOT EXISTS idx_analytics_views_owner ON analytics_views(owner_user_id, updated_at DESC);
        CREATE INDEX IF NOT EXISTS idx_analytics_views_role ON analytics_views(role_default);
        CREATE TABLE IF NOT EXISTS deployment_revisions (
            revision_id TEXT PRIMARY KEY,
            target TEXT NOT NULL CHECK(target IN ('compose','helm')),
            parent_revision_id TEXT,
            status TEXT NOT NULL CHECK(status IN (
                'draft','approved','applying','active','failed','rolled_back','superseded','rejected'
            )),
            values_encrypted TEXT NOT NULL,
            changed_keys TEXT NOT NULL,
            rendered_preview TEXT,
            preview_digest TEXT,
            exception_expires_at TEXT,
            created_by TEXT NOT NULL,
            approved_by TEXT,
            applied_at TEXT,
            health TEXT,
            error TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_deploy_rev_target ON deployment_revisions(target, created_at DESC);
        CREATE TABLE IF NOT EXISTS pending_mfa_enrollments (
            user_id TEXT PRIMARY KEY REFERENCES users(user_id) ON DELETE CASCADE,
            secret_encrypted TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS mfa_login_challenges (
            challenge_hash TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_mfa_login_challenges_user ON mfa_login_challenges(user_id);
    """)


def downgrade() -> None:
    op.execute("""
        DROP TABLE IF EXISTS auth.mfa_login_challenges CASCADE;
        DROP TABLE IF EXISTS auth.pending_mfa_enrollments CASCADE;
        DROP TABLE IF EXISTS auth.deployment_revisions CASCADE;
        DROP TABLE IF EXISTS auth.analytics_views CASCADE;
        DROP TABLE IF EXISTS auth.stored_credentials CASCADE;
        DROP TABLE IF EXISTS auth.user_sites CASCADE;
        DROP TABLE IF EXISTS auth.runtime_settings CASCADE;
        DROP TABLE IF EXISTS auth.reports CASCADE;
        DROP TABLE IF EXISTS auth.legacy_migrations CASCADE;
        DROP TABLE IF EXISTS auth.jobs CASCADE;
        DROP TABLE IF EXISTS auth.audit_events CASCADE;
        DROP TABLE IF EXISTS auth.recovery_codes CASCADE;
        DROP TABLE IF EXISTS auth.password_resets CASCADE;
        DROP TABLE IF EXISTS auth.invitations CASCADE;
        DROP TABLE IF EXISTS auth.auth_sessions CASCADE;
        DROP TABLE IF EXISTS auth.users CASCADE;
        DROP TABLE IF EXISTS auth.schema_version CASCADE;
    """)
