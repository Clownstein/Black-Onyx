# Configuration reference

Administrators can change day-to-day runtime configuration from **Administration → Settings**. The browser editor covers LLM provider routing, model names, compatible base URLs, write-only API keys, RAG behavior, ingestion limits and processing defaults, chunking, feed policy, and Qdrant connectivity. Changes are validated, audited, persisted in the canonical state database, and hot-applied to newly initialized services.

Stored secrets are encrypted and are never returned by the API; the UI only reports whether a key is configured. Clearing a UI-managed secret falls back to its deployment environment value. Runtime UI overrides take precedence over YAML/environment values until changed again. Deployment-only security, filesystem roots, SMTP, and model mount paths remain intentionally unavailable in the browser.

Copy `config.example.yaml` to ignored `config.yaml`. Nested settings can be overridden with `QDRANT_` environment variables and double underscores, for example `QDRANT_SECURITY__PRODUCTION=true`. Secrets should use their dedicated environment-variable references instead of YAML values.

## Storage and ingestion

- `storage.state_dir` contains the canonical authentication database, uploads, reports, job history, service databases, and migration backups.
- `ingestion.allowed_data_roots` confines administrator server-directory ingestion.
- `ingestion.max_upload_bytes` and `max_upload_files` bound browser uploads.
- ingestion model, chunking, classifier, NER, OCR, image, and CSV options control the shared document pipeline.

## Authentication and network

- `security.external_url` is the exact browser origin and must be HTTPS in production.
- `allowed_hosts` protects the Host header; `allowed_origins` is for deliberately separate browser origins and defaults empty.
- `trusted_proxies` lists the only proxy CIDRs whose forwarding headers may be honored.
- `auth_secret_env` names the preferred environment variable holding the encryption/token secret (default `BLACK_ONYX_AUTH_SECRET`). Startup fails when neither that name nor the legacy `DEFENDERS_CHAT_AUTH_SECRET` is set, including in local development.
- Compose / Vite helpers: `BLACK_ONYX_PORT` (host publish / dev proxy), `BLACK_ONYX_MODEL_DIR`, and production `BLACK_ONYX_EXTERNAL_URL` / `BLACK_ONYX_ALLOWED_HOSTS` / `BLACK_ONYX_HOSTNAME`.
- `secure_cookies`, `session_idle_minutes`, and `session_absolute_hours` control session cookies and expiry.
- `production` enables fail-closed validation; `docs_enabled` does not make documentation public in production.

## Providers and RAG

`llm.provider` selects the default. Each chat session binds its provider when created. Provider API-key settings name environment variables. `llm.rag.enabled` controls retrieval; collections, result count, threshold, neighbor window, and the evidence-only system prompt are configured below `llm.rag`.

Enrichment provider names, timeout, concurrency, and cache lifetime are below `enrichment`. Keep actual keys in the provider environment variables. The capability API reports names and availability, never values.

## Feeds and ATT&CK

`feeds.allowed_hosts` is mandatory for network polling. Response bytes and global concurrency are bounded. TAXII feed records store `password_env`; set that named variable in the runtime secret store.

ATT&CK refresh remains disabled until both `threat_intel.mitre_attack_source_url` and the matching SHA-256 digest are configured. The source must be HTTPS and fit `mitre_attack_max_bytes`; no refresh occurs automatically at startup.

## Images

`image.dedup_threshold` controls collection-scoped perceptual-hash matching. CLIP and OCR settings select models/devices. Browser image search and vision chat use temporary bounded uploads; server paths are never accepted from browser requests.
