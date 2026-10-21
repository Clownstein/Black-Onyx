"""TIP schema tables (unified former per-file SQLite stores)."""

from typing import Sequence, Union

from alembic import op

revision: str = "0003"
down_revision: Union[str, None] = "0002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("SET search_path TO tip")
    op.execute("""
        CREATE TABLE IF NOT EXISTS feeds (
            name TEXT PRIMARY KEY,
            url TEXT NOT NULL,
            feed_type TEXT NOT NULL,
            collection TEXT,
            enabled INTEGER DEFAULT 1,
            poll_interval_minutes INTEGER DEFAULT 60,
            last_poll TIMESTAMP,
            config TEXT,
            last_attempt TIMESTAMP,
            last_status TEXT,
            last_error TEXT,
            last_items INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS seen_items (
            feed_name TEXT NOT NULL,
            item_url TEXT NOT NULL,
            first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (feed_name, item_url)
        );
        CREATE TABLE IF NOT EXISTS connectors (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            connector_type TEXT NOT NULL,
            base_url TEXT NOT NULL,
            tenant_id TEXT,
            collection TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            poll_interval_minutes INTEGER NOT NULL DEFAULT 60,
            last_poll_at TEXT,
            last_poll_status TEXT,
            last_poll_error TEXT,
            config_json TEXT NOT NULL DEFAULT '{}',
            credential_env_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            last_success_at TEXT,
            push_token_hash TEXT,
            push_token_prefix TEXT,
            last_failure_at TEXT,
            consecutive_failures INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS connector_cursors (
            connector_id TEXT PRIMARY KEY REFERENCES connectors(id) ON DELETE CASCADE,
            cursor_value TEXT,
            last_seen_at TEXT
        );
        CREATE TABLE IF NOT EXISTS seen_detections (
            connector_id TEXT NOT NULL,
            detection_key TEXT NOT NULL,
            first_seen_at TEXT NOT NULL,
            PRIMARY KEY (connector_id, detection_key)
        );
        CREATE TABLE IF NOT EXISTS connector_asset_outbox (
            id SERIAL PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            asset_id TEXT NOT NULL,
            hostname TEXT NOT NULL DEFAULT '',
            ip_address TEXT NOT NULL DEFAULT '',
            username TEXT NOT NULL DEFAULT '',
            source TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            attempt_count INTEGER NOT NULL DEFAULT 0,
            next_attempt_at TEXT NOT NULL,
            last_error TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE (tenant_id, asset_id, source)
        );
        CREATE TABLE IF NOT EXISTS detection_dispositions (
            detection_key TEXT PRIMARY KEY,
            connector TEXT,
            title TEXT,
            disposition TEXT,
            disposition_by TEXT,
            disposition_note TEXT,
            disposition_at TEXT,
            acknowledged INTEGER NOT NULL DEFAULT 0,
            acknowledged_at TEXT,
            promoted_case_id TEXT
        );
        CREATE TABLE IF NOT EXISTS watchlists (
            list_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS watchlist_items (
            item_id TEXT PRIMARY KEY,
            list_id TEXT NOT NULL REFERENCES watchlists(list_id),
            ioc_type TEXT NOT NULL,
            ioc_value TEXT NOT NULL,
            added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            notes TEXT,
            suppressed INTEGER DEFAULT 0,
            confidence REAL DEFAULT 1.0
        );
        CREATE TABLE IF NOT EXISTS alerts (
            alert_id TEXT PRIMARY KEY,
            list_id TEXT NOT NULL REFERENCES watchlists(list_id),
            item_id TEXT NOT NULL,
            triggered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            collection TEXT,
            point_id TEXT,
            context TEXT,
            acknowledged INTEGER DEFAULT 0,
            acknowledged_at TIMESTAMP,
            disposition TEXT,
            disposition_by TEXT,
            disposition_note TEXT,
            promoted_case_id TEXT
        );
        CREATE TABLE IF NOT EXISTS webhooks (
            webhook_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            token_hash TEXT NOT NULL UNIQUE,
            token_prefix TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_used_at TIMESTAMP,
            event_count INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS webhook_events (
            event_id TEXT PRIMARY KEY,
            webhook_id TEXT NOT NULL,
            webhook_name TEXT NOT NULL,
            source TEXT,
            ioc_count INTEGER NOT NULL DEFAULT 0,
            iocs_json TEXT NOT NULL DEFAULT '{}',
            alert_ids_json TEXT NOT NULL DEFAULT '[]',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            acknowledged INTEGER NOT NULL DEFAULT 0,
            acknowledged_at TIMESTAMP,
            disposition TEXT,
            disposition_by TEXT,
            disposition_note TEXT,
            disposition_at TIMESTAMP,
            promoted_case_id TEXT
        );
        CREATE TABLE IF NOT EXISTS annotations (
            annotation_id TEXT PRIMARY KEY,
            collection TEXT NOT NULL,
            point_id TEXT NOT NULL,
            author TEXT,
            content TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS tags (
            tag_id TEXT PRIMARY KEY,
            collection TEXT NOT NULL,
            point_id TEXT NOT NULL,
            tag TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS notes (
            note_id TEXT PRIMARY KEY,
            collection TEXT NOT NULL,
            point_id TEXT NOT NULL,
            author TEXT,
            content TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS bookmarks (
            bookmark_id TEXT PRIMARY KEY,
            collection TEXT NOT NULL,
            point_id TEXT NOT NULL,
            "user" TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS confidence (
            collection TEXT NOT NULL,
            point_id TEXT NOT NULL,
            confidence_score REAL,
            author TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (collection, point_id)
        );
        CREATE TABLE IF NOT EXISTS status (
            collection TEXT NOT NULL,
            point_id TEXT NOT NULL,
            status TEXT,
            author TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (collection, point_id)
        );
        CREATE TABLE IF NOT EXISTS ioc_tracking (
            ioc_type TEXT NOT NULL,
            ioc_value TEXT NOT NULL,
            first_seen TIMESTAMP,
            last_seen TIMESTAMP,
            sighting_count INTEGER DEFAULT 1,
            source_count INTEGER DEFAULT 1,
            decay_score REAL DEFAULT 1.0,
            last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (ioc_type, ioc_value)
        );
        CREATE TABLE IF NOT EXISTS ioc_sources (
            ioc_value TEXT NOT NULL,
            source TEXT NOT NULL,
            first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (ioc_value, source)
        );
        CREATE TABLE IF NOT EXISTS cases (
            case_id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            description TEXT,
            status TEXT DEFAULT 'open',
            priority TEXT DEFAULT 'medium',
            severity TEXT,
            assignee TEXT,
            tags TEXT,
            external_incident_id TEXT,
            detected_at TIMESTAMP,
            contained_at TIMESTAMP,
            closed_at TIMESTAMP,
            sla_due_at TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS case_iocs (
            id SERIAL PRIMARY KEY,
            case_id TEXT NOT NULL REFERENCES cases(case_id),
            ioc_type TEXT NOT NULL,
            ioc_value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS case_points (
            id SERIAL PRIMARY KEY,
            case_id TEXT NOT NULL REFERENCES cases(case_id),
            collection_name TEXT NOT NULL,
            point_id TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS case_notes (
            note_id TEXT PRIMARY KEY,
            case_id TEXT NOT NULL REFERENCES cases(case_id),
            author TEXT,
            content TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS case_timeline (
            event_id TEXT PRIMARY KEY,
            case_id TEXT NOT NULL REFERENCES cases(case_id),
            event_type TEXT,
            description TEXT,
            author TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS assets (
            asset_id TEXT PRIMARY KEY,
            hostname TEXT,
            ip_address TEXT,
            asset_type TEXT DEFAULT 'host',
            owner TEXT,
            criticality TEXT DEFAULT 'medium',
            tags TEXT DEFAULT '[]',
            notes TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS asset_case_links (
            asset_id TEXT NOT NULL,
            case_id TEXT NOT NULL,
            linked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (asset_id, case_id)
        );
        CREATE TABLE IF NOT EXISTS posture_findings (
            finding_id TEXT PRIMARY KEY,
            asset_id TEXT,
            title TEXT NOT NULL,
            severity TEXT DEFAULT 'medium',
            status TEXT DEFAULT 'open',
            category TEXT DEFAULT 'misconfiguration',
            description TEXT DEFAULT '',
            source TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_assets_hostname ON assets(hostname);
        CREATE INDEX IF NOT EXISTS idx_assets_ip ON assets(ip_address);
        CREATE INDEX IF NOT EXISTS idx_findings_status ON posture_findings(status);
        CREATE TABLE IF NOT EXISTS detection_rules (
            rule_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            rule_type TEXT NOT NULL,
            content TEXT NOT NULL,
            status TEXT DEFAULT 'draft',
            source TEXT DEFAULT 'authored',
            author TEXT DEFAULT '',
            tags TEXT DEFAULT '[]',
            validation_ok INTEGER DEFAULT 0,
            validation_errors TEXT DEFAULT '[]',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            submitted_at TIMESTAMP,
            approved_at TIMESTAMP,
            approved_by TEXT
        );
        CREATE TABLE IF NOT EXISTS collections (
            collection_id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            description TEXT,
            enabled INTEGER NOT NULL DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS objects (
            collection_id TEXT NOT NULL,
            object_id TEXT NOT NULL,
            stix_json TEXT NOT NULL,
            created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (collection_id, object_id)
        );
        CREATE INDEX IF NOT EXISTS idx_objects_collection ON objects(collection_id, created);
        CREATE TABLE IF NOT EXISTS api_keys (
            key_id TEXT PRIMARY KEY,
            token_hash TEXT NOT NULL UNIQUE,
            token_prefix TEXT NOT NULL,
            name TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1
        );
        CREATE INDEX IF NOT EXISTS idx_taxii_keys_hash ON api_keys(token_hash);
        CREATE TABLE IF NOT EXISTS audit (
            id SERIAL PRIMARY KEY,
            key_id TEXT,
            action TEXT NOT NULL,
            detail TEXT,
            at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS processed_items (
            file_hash TEXT NOT NULL,
            chunk_index INTEGER NOT NULL,
            filepath TEXT NOT NULL,
            collection TEXT NOT NULL,
            processed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (file_hash, chunk_index, collection)
        );
        CREATE TABLE IF NOT EXISTS ingestion_runs (
            run_id TEXT PRIMARY KEY,
            directory TEXT NOT NULL,
            collection TEXT NOT NULL,
            total_files INTEGER,
            processed_files INTEGER DEFAULT 0,
            started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            completed_at TIMESTAMP,
            status TEXT DEFAULT 'running'
        );
        CREATE TABLE IF NOT EXISTS sessions (
            session_id TEXT PRIMARY KEY,
            owner_id TEXT NOT NULL DEFAULT '',
            title TEXT,
            provider TEXT,
            model TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS messages (
            id SERIAL PRIMARY KEY,
            session_id TEXT NOT NULL REFERENCES sessions(session_id),
            role TEXT NOT NULL,
            content TEXT NOT NULL,
            images TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS settings (
            id INTEGER PRIMARY KEY,
            url TEXT NOT NULL DEFAULT '',
            api_key_env TEXT NOT NULL DEFAULT 'MISP_API_KEY',
            enabled INTEGER NOT NULL DEFAULT 0,
            collection TEXT NOT NULL DEFAULT 'all-knowledge',
            last_sync TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS synced_events (
            event_id TEXT PRIMARY KEY,
            uuid TEXT,
            info TEXT,
            synced_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS synced_iocs (
            event_id TEXT NOT NULL,
            ioc_type TEXT NOT NULL,
            ioc_value TEXT NOT NULL,
            collection TEXT NOT NULL DEFAULT '',
            synced_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (event_id, ioc_type, ioc_value)
        );
        CREATE TABLE IF NOT EXISTS published (
            case_id TEXT NOT NULL,
            misp_event_id TEXT NOT NULL,
            published_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (case_id, misp_event_id)
        );
        CREATE TABLE IF NOT EXISTS enrichment_cache (
            cache_key TEXT PRIMARY KEY,
            provider TEXT NOT NULL,
            ioc_type TEXT,
            ioc_value TEXT,
            result_json TEXT NOT NULL,
            cached_at REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS playbooks (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            trigger_type TEXT NOT NULL,
            steps_json TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS runs (
            run_id TEXT PRIMARY KEY,
            playbook_id TEXT NOT NULL REFERENCES playbooks(id),
            status TEXT NOT NULL,
            context_json TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            finished_at TIMESTAMP,
            initiated_by TEXT DEFAULT '',
            approved_by TEXT,
            approved_at TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS run_steps (
            id SERIAL PRIMARY KEY,
            run_id TEXT NOT NULL REFERENCES runs(run_id),
            step_index INTEGER NOT NULL,
            step_type TEXT NOT NULL,
            status TEXT NOT NULL,
            result_json TEXT
        );
        CREATE TABLE IF NOT EXISTS outbound_endpoints (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            url TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1
        );
    """)


def downgrade() -> None:
    op.execute("DROP SCHEMA IF EXISTS tip CASCADE")
