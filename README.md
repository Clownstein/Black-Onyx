# Black Onyx

> **Project status — work in progress:** Black Onyx is under active development and is
> not complete or production-ready. Features, APIs, schemas, deployment behavior, and
> security controls may change. Validate the system in an isolated environment before
> considering any production use.

Black Onyx is an invite-only **threat-intelligence workspace** (TIP-first) for blue-team investigation, with an absorbed **detection spine** (Kafka/Postgres anomaly pipeline, incidents, hunt, SOAR). It is not a SIEM replacement: it helps analysts ingest evidence, work IOCs, triage alerts and connector detections, correlate multi-model findings into incidents, manage cases and assets, and measure operational CTI impact—with a secured React UI, versioned FastAPI API, SQLite TIP state, Postgres detection state, and Qdrant vector search.

Documentation:

- [Feature guide](docs/FEATURES.md) — workflows, gallery hub, analytics, triage, connectors, backup
- [Brand kit](docs/brand/README.md) — colors, logo, background, typography
- [Secured API reference](docs/API.md)
- [Security operations](docs/SECURITY.md)
- [Migration and backup](docs/MIGRATIONS.md)
- [Configuration reference](docs/CONFIGURATION.md)
- [Deployment guide](docs/DEPLOYMENT.md)
- [Development and verification](docs/DEVELOPMENT.md)

## What you can do

| Area | Capabilities |
|---|---|
| Evidence | Bounded uploads, admin-scoped directory ingest, OCR/CLIP images, semantic and image search, collections with annotations |
| Investigation | RAG chat, KQL/SPL-style **Query**, entity **Graph**, cases with timelines and MISP publish |
| Intelligence | IOC extract/enrich/score, STIX export, ATT&CK heatmap (risk-weighted, not vanity 100% coverage), Sigma/YARA generate and store, reports |
| Operations | Unified **Triage**, watchlists/alerts, SIEM/EDR **connectors**, streaming **detection** (ingest→Kafka→findings→incidents), hunt, SOAR response queue, playbooks, TAXII/MISP publishing, asset CMDB/posture, security profiles, malware lab orchestration |
| Analytics | Disposition-aware MTTA/MTTR/FPR, alert/detection timeseries, intel age, enrichment coverage, fresh vs stale IOCs, connector health, detection data-health, saved views |
| Continuity | Admin **backup/restore** of SQLite state plus Qdrant snapshots (create, download, upload, restore) |
| Workspace UX | Immersive **Gallery** hub at `/`, classic shell for workflow pages, Black Onyx brand theme (violet/silver on `#0B0B0E`, Sora + IBM Plex Sans), light/dark + accent swatches |

## Security model

- Accounts are created only from 24-hour, role-bound invitations (`admin`, `analyst`, read-only `viewer`).
- Passwords use Argon2id. Sessions are opaque, server-side, idle/absolute-expiring, same-origin + CSRF (`blackonyx_session` / `blackonyx_csrf`; `__Host-` prefix when secure cookies are on).
- Optional TOTP MFA with one-time recovery codes.
- Production fails closed unless the external URL is HTTPS, secure cookies are enabled, and `BLACK_ONYX_AUTH_SECRET` is present (legacy `DEFENDERS_CHAT_AUTH_SECRET` is still accepted).
- Browser uploads stay under application state. Server-directory ingestion is admin-only within configured roots.
- Feed URLs require HTTPS, hostname allowlist, public DNS, bounded responses, and redirect revalidation.
- Connector/webhook machine tokens skip browser CSRF only when the token header is present; session browser calls still require CSRF and origin checks.
- Supported HTTP API lives under `/api/v1` only.

Sit Black Onyx behind a trusted TLS reverse proxy. Do not expose the application container or Qdrant on an untrusted network.

## Local setup on Windows

Requires Python 3.12 or newer. The root application consumes the shared
`black-onyx-contracts` workspace package used by the detection services.

```powershell
Copy-Item config.example.yaml config.yaml
$env:BLACK_ONYX_AUTH_SECRET = -join ((1..64) | ForEach-Object { '{0:x}' -f (Get-Random -Maximum 16) })
python -m venv .venv
.\.venv\Scripts\Activate.ps1
uv sync --extra image --extra llm --extra threat-intel --extra dev
Push-Location web
npm install
node node_modules/typescript/bin/tsc -b
node node_modules/vite/bin/vite.js build --configLoader runner
Pop-Location
uv run black-onyx users bootstrap-admin --email admin@example.com
uv run black-onyx-web --host 127.0.0.1 --port 8000
```

Bootstrap prompts for the password and refuses to run after any user exists. Open `http://127.0.0.1:8000`, sign in, then create invitations from Administration.

Keep the authentication secret stable. Changing it invalidates token hashes and makes encrypted MFA, runtime, and site-credential secrets unreadable.

CLI entry points: `black-onyx` (ingest, search, users, …) and `black-onyx-web` (API + UI). The Python package is `black_onyx`.

## Docker

Create a local model directory if needed; GGUF files are excluded from image layers and build context.

```powershell
New-Item -ItemType Directory -Force models
Copy-Item .\ALBotClownstein.gguf .\models\
$env:BLACK_ONYX_AUTH_SECRET = "replace-with-a-generated-long-random-secret"
docker compose build
docker compose run --rm cli users bootstrap-admin --email admin@example.com
docker compose up -d
```

Development Compose binds the app and Qdrant to loopback. Override publish port with `BLACK_ONYX_PORT` (for example `8100`). Vite’s dev proxy reads the same variable from the project-root `.env`.

Production:

```powershell
$env:BLACK_ONYX_AUTH_SECRET = "generated-secret-from-a-secret-manager"
$env:BLACK_ONYX_EXTERNAL_URL = "https://blackonyx.example.com"
$env:BLACK_ONYX_ALLOWED_HOSTS = '["blackonyx.example.com"]'
$env:BLACK_ONYX_HOSTNAME = "blackonyx.example.com"
docker compose -f docker-compose.yml -f docker-compose.production.yml up -d --build
```

The production override removes direct host ports, uses an internal backend network, and terminates TLS at pinned Caddy (`deploy/nginx.conf.example` for Nginx). Store auth, SMTP, TAXII, and provider keys in secrets—not in the image or repository.

Named Docker volumes intentionally keep the historical `defenderchat_*` names so rebuilds and rebrands do not orphan multi-GB model/Qdrant data onto empty `blackonyx_*` volumes. Do not rename those volumes unless you are migrating data on purpose.

## Configuration

Start from `config.example.yaml`. Important settings include:

- `storage.state_dir`: SQLite state, uploads, reports, backups, and service databases.
- `security.external_url`, `allowed_hosts`, `allowed_origins`, `trusted_proxies`, and `auth_secret_env` (default `BLACK_ONYX_AUTH_SECRET`).
- `ingestion.allowed_data_roots`, upload byte/file limits.
- `feeds.allowed_hosts` and bounded response settings.
- `threat_intel.mitre_attack_source_url` plus required SHA-256 pin (ATT&CK is never downloaded implicitly).

## Backup and migration

Prefer **Administration → Continuity** (or `/api/v1/admin/backup/*`) for consistent SQLite + Qdrant snapshot packages. For filesystem backups, stop the app when possible and copy the entire `storage.state_dir` together with Qdrant storage or a Qdrant snapshot. SQLite uses WAL mode—include `-wal`/`-shm` if a live copy is unavoidable.

Schema migrations are transactional at startup. Preserve checkpoints until the secured application and collection contents are verified. See [MIGRATIONS.md](docs/MIGRATIONS.md). Detection-plane stack (same Compose project as TIP):

```bash
docker compose -f docker-compose.yml -f docker-compose.platform.yml up -d
docker compose -f docker-compose.yml -f docker-compose.platform.yml -f docker-compose.detection-core.yml up -d --build
powershell -File scripts/smoke_detection_infra.ps1
```

Full detection services: add `-f docker-compose.detection-apps.yml`. See [ABSORPTION_CHECKLIST.md](docs/ABSORPTION_CHECKLIST.md).

## Verification

```powershell
$env:PYTHONPATH = "src"
.\.venv\Scripts\python.exe -m pytest -q --basetemp=.pytest-tmp\verification
.\.venv\Scripts\python.exe -m compileall -q src
Push-Location web
node node_modules/typescript/bin/tsc -b
node node_modules/vite/bin/vite.js build --configLoader runner
Pop-Location
$env:BLACK_ONYX_AUTH_SECRET = "compose-validation-only"
docker compose config --quiet
```

Security tooling: Ruff, mypy, Bandit, pip-audit, npm audit, and pre-commit. Review dependency audit findings before production release.

## License

MIT. See `LICENSE`.
