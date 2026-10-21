# Features

Browser APIs use `/api/v1`, the session cookie, same-origin checks, and CSRF on
unsafe methods (machine connector/webhook tokens are the exception).

Black Onyx is a **TIP-first investigation workspace**: evidence, CTI, triage, light automation, and disposition-aware analytics, not a full EDR console or log SIEM.

## Interface and workspace design

After sign-in, `/` is the immersive **Gallery** hub: pan across role-filtered tiles for every built-in route, plus optional user-added external sites (with encrypted credential reveal). Gallery motion and WebGL effects are tuned for stability, and Analytics tiles include sparkline previews. Exit to the classic dashboard via the brand control, or open any tile into the shared **classic shell** (sidebar + top bar).

The React UI uses repository-root `BlackOnyxBackground.png` (served as `/background.png`) on auth screens and `BlackOnyxTransparentLogo.png` (served as `/logo.png`) in the shell, gallery, and sign-in hero. Brand tokens (deep `#0B0B0E`, silver `#A9ADB6`, violet `#6C3CF2` / `#A78BFA`, Sora + IBM Plex Sans) live in `web/src/styles.css`; see [docs/brand/README.md](brand/README.md). Headings, empty states, notices, and confirmations are in `web/src/ui.tsx`. Theme preference persists under `blackonyx_theme_v1` (default accent: Onyx violet).

Navigation groups cover overview, investigation, intelligence, operations, and admin controls. Role gating is centralized (`visibleFor`); the gallery and sidebar share that predicate.

## Workspace settings

Administrators use **Settings** for provider/model selection, Ollama and OpenAI-compatible base URLs, write-only OpenAI/Anthropic/Gemini credentials, RAG, ingestion and upload limits, chunking, feed polling and hostname policy, and Qdrant connection values. Secrets cannot be read back. Changes are validated and hot-applied to future jobs and provider sessions. Local GGUF models connect through the isolated OpenAI-compatible llama server.

## Accounts and roles

The first administrator is created only with `black-onyx users bootstrap-admin`. Administrators create 24-hour, single-use invitations from **Administration** (`admin`, `analyst`, or `viewer`). SMTP delivery is optional; otherwise copy the URL.

Users can sign in with password and optional TOTP or recovery code, request a non-enumerating password reset, change password, enroll MFA, and save hashed recovery codes. Password changes, resets, disablement, and role changes invalidate affected sessions.

- **Administrators:** users, invitations, feeds, ATT&CK refresh, collection deletion, connectors, backup/restore, role-default analytics views.
- **Analysts:** investigations, triage dispositions, feed poll, playbook runs, detections promote/acknowledge.
- **Viewers:** dashboards, results, cases, alerts, graphs, reports, bookmarks, and capability status (read-only).

## Dashboard and jobs

**Dashboard** shows collection counts, indexed points, active jobs, Qdrant state, and ops KPI deep-links (alerts, cases, fresh/stale IOCs, recent detections). **Jobs** lists the current user’s ingestion jobs; stoppable states include `queued`, `running`, `stopping`, `stopped`, `completed`, `failed`. Records expire after 30 days.

## Evidence ingestion

**Ingest** accepts bounded multipart uploads into a per-user, per-job state directory. Browser callers cannot submit arbitrary server paths. Administrators may use server-directory ingestion only within `ingestion.allowed_data_roots`; unrestricted local paths remain CLI-only (`black-onyx ingest`).

Ingestion fingerprints content and processing config, writes Qdrant before committing checkpoints, handles changed/stale chunks, serializes CSV, deduplicates images by perceptual hash, records IOC sightings, and checks watchlists.

## Semantic search, image search, and Query

**Search** embeds a text query against a Qdrant collection. **Image search** accepts a bounded upload, embeds with CLIP, deletes the temp file, and searches the collection image vector (unavailable when image dependencies are disabled; see **System**).

**Query** offers KQL/SPL-style filters over alerts, cases, detections, and related evidence for investigation pivots (not a full log SIEM). Saved queries persist in the browser under `blackonyx_saved_queries_v1`.

## Collections and point analysis

**Collections** uses opaque pagination cursors. Selecting a point reveals its payload. Analysts can add annotations, notes, tags, bookmarks, confidence, and IOC disposition. Identity always comes from the authenticated user. Administrators delete a collection only after typing its exact name.

## Chat and RAG

Chat sessions are private to their owner and bind provider/model at creation. Responses stream over CSRF-protected `POST` and can be cancelled. With RAG disabled, chat uses the bound provider directly. With RAG enabled, retrieved documents are treated as untrusted evidence, not instructions. Raw HTML in Markdown is ignored.

Vision-capable providers accept one to five image uploads through the multipart chat endpoint. Images are size/type checked, kept only for the provider call, then removed.

### Chat settings drawer (llama.cpp-style)

The chat UI includes a collapsible settings drawer with runtime model configuration:

- **Temperature** slider (0.0–2.0)
- **Max tokens** input (1–32768)
- **Thinking level** selector (OFF/LOW/MEDIUM/HIGH): maps to Gemma 4 system prompt fragments
- **System prompt override** textarea: replaces the config default for plain and RAG turns

Settings apply to plain and RAG chat turns. MCP tool turns use the tool-declaration
system prompt (overrides do not apply to the MCP orchestrator).

### MCP tools in chat

Enable the **MCP tools** toggle in the chat composer to run the 63-tool agent loop
inline. The loop includes 18 platform tools (evidence search, IOC enrich, case assist,
rule draft, etc.) and 45 security tools (nmap, sqlmap, binary RE, crypto/DFIR, Web3).
Tool calls and results stream back as SSE `tool` events and appear as inline tool cards
in the chat stream.

MCP tools and web search are mutually exclusive in a single chat turn.

## Security Lab

The Security Lab (`/security-lab`) exposes 45 defensive security tools through the
BFF. Tools are grouped into five categories:

| Category | Tools |
| --- | --- |
| Sandbox | Read, Write, Edit, Grep, Glob, ListFiles, Bash |
| Network Scanners | nmap, sqlmap, nikto, whois, shodan, gobuster, hydra, tcpdump, port_scan |
| Binary RE | checksec, decompile, disassemble, extract_strings, run_binary, file_info, search_gadgets, cyclic_pattern |
| Crypto / DFIR | aes_encrypt/decrypt, decode/encode (hex, base64), hash_data, extract_iocs, compute_threat_score, add_ioc_to_case, generate_yara_rule, analyze_pcap |
| Web3 | cast_call, cast_send, cast_keccak, compile_contracts, analyze_contract, get_contract_storage, check_solved, submit_solution |

Each tool has a JSON schema form for its arguments. Availability depends on the
configured tool gate, sandbox-image capability attestation, and enforced egress;
tools without a safe implementation remain unavailable rather than running a
stand-in (see [SECURITY_TOOLS.md](SECURITY_TOOLS.md)). Non-read actions use a
preview followed by a durable, single-use server approval bound to the actor and
request. A UI checkbox or model-supplied `confirm` value is never approval. The
agent panel pauses at the first non-read action until that approval is granted.

See [BLACK_ONYX_5B_INTEGRATION.md](BLACK_ONYX_5B_INTEGRATION.md) for the LLM backend
and [MODELS.md](../MODELS.md) for the full model architecture.

## IOC workbench

Extract and normalize indicators, optionally enrich through configured providers, compute a composite score, and export a STIX 2.1 bundle. Provider selection, concurrency, cache duration, and timeout are configurable. Client errors never expose provider keys or raw internal exceptions. CVE / EPSS / KEV-oriented widgets surface risk context where data is available.

## MITRE ATT&CK

Search techniques, extract IDs from text, build tactic heatmaps, and create ATT&CK relationship graphs. Coverage analytics are **risk-weighted**; chasing 100% technique coverage is not a success metric. No startup download occurs. Administrators refresh the cache only from a configured HTTPS URL whose content matches `mitre_attack_source_sha256`.

## Detection rules and graphs

**Rules** generates Sigma or YARA text from reviewed IOC JSON and can persist rules for validate / dry-run / export / analytics. Rules are never executed against production telemetry inside Black Onyx. **Graph** builds entity relationships from payload arrays or ATT&CK technique IDs for analyst review, not proof of attribution.

## Reports and content

Reports accept structured IOC, enrichment, ATT&CK, and optional case context. Markdown is escaped, HTML allowlist-sanitized, and PDF rendering receives no external base URL. Generated reports are shared operational records (viewers read-only). **Content** surfaces the reports library, digests, and playbook documentation entry points.

## Cases

Cases include title, description, priority, assignee, tags, status, IOCs, Qdrant point references, notes, timeline, and optional MISP publishing. Analysts transition status, attach evidence, and add notes. Deletion uses typed confirmation.

## Unified triage

**Triage** merges watchlist alerts, connector detections, and webhook events into one queue. Analysts can acknowledge, disposition (including false-positive paths that feed FPR), and **promote** items into cases with atomic linking. Linked case IDs surface on the item after promote.

## Watchlists and alerts

Watchlists hold IOC type/value pairs. Successful ingestion checks observations and creates deduplicated alerts with collection, point, source, and context. Disposition of noisy false positives supports suppression workflows; noisy-IOC leaderboards appear on watchlists and analytics.

## Connectors and detections

**Detections** manages pull-based SIEM/EDR connectors (generic REST, Microsoft Defender for Endpoint, CrowdStrike Falcon), poll/test, recent detections, disposition/ack columns, and **push tokens** for machine-authenticated ingest (`X-Connector-Token` / Bearer). Push endpoints skip browser CSRF only when a machine token header is present.

## Feeds, webhooks, publishing

Feeds support RSS, Atom, and TAXII with HTTPS allowlisting, DNS pinning, and bounded responses. TAXII passwords use `password_env`. Administrators define/delete feeds; analysts may poll approved feeds.

Inbound **webhooks** accept token-authenticated events. **Publishing** covers MISP sync and outbound TAXII collections for sharing STIX.

## Assets

**Assets** is a lightweight CMDB: inventory CRUD, CSV import, posture findings board, criticality exposure, and case linking. Related alerts/detections/IOCs can be suggested by hostname or IP for investigation pivots.

## Playbooks

Define enable/disable playbooks and run step sequences for light automation (for example rule generation helpers). Playbook analytics appear on the analytics surface. This is not a full SOAR product.

## Analytics

**Analytics** provides disposition-aware operational KPIs and charts, including:

- overview KPIs and timeseries (alerts, detections, fresh/stale IOCs)
- MTTA / MTTR / FPR (FPR = FP / (TP + FP)), reopen rate, alert–case ratio
- detections by connector, connector health
- intel age, enrichment coverage, CTI impact / intel yield
- ATT&CK sightings vs claimed rules (risk-weighted)
- TAXII publish volume, CVE risk board (EPSS × KEV where available)
- asset criticality exposure, case status funnel, playbook stats
- saved views (personal; role-default views are admin-managed)

Deep-links into triage, cases, detections, decay, IOCs, assets, and publishing keep analytics actionable rather than vanity dashboards.

## IOC decay and bookmarks

IOC sightings update collection-aware freshness and source counts. **Decay** shows tracked, fresh, and stale indicators and recalculation. **Bookmarks** are per authenticated user.

## Gallery sites and credentials

Users can add external sites as gallery tiles, probe framing, fetch favicons served from Black Onyx, and optionally store encrypt-at-rest login material for copy/paste reveal (never silently POSTed to third parties). Reveal is rate-limited and audited.

## Continuity (backup and restore)

Administrators use **Administration → Continuity** (or `/api/v1/admin/backup/*`) to create zip packages of application state and Qdrant snapshots, list/download/upload/delete backups, and restore. Prefer this over ad-hoc file copies when both SQLite and vectors must stay consistent.

## System capabilities

**System** reports enabled features, configured provider names, and safe disabled-feature reasons. It does not return keys, SMTP configuration, state paths, or data roots.

## Detection plane

Detection console routes share the Black Onyx session and CSRF shell. Browser traffic uses `/api/v1/detection/*` BFF proxies. Postgres is the system of record for incidents (`incident-api`) and assets (`asset-registry`).

**Prerequisite:** detection upstreams must be reachable from the TIP process. Defaults use Compose DNS. Host TIP needs `BLACK_ONYX_*_URL` overrides ([CONFIGURATION.md](CONFIGURATION.md)). If upstreams are down, pages such as `/incidents`, `/findings`, `/hunt`, and `/malware` show **API 502** `Detection upstream unavailable: ConnectError`, which is expected when only the TIP is running. Use **Detection → Services** (or loopback `/health/live`) to monitor.

| Route | Purpose |
|---|---|
| `/detection` | Detection overview |
| `/incidents` / `/findings` | Correlated incidents and modality findings |
| `/hunt` | OpenSearch (+ optional federated vector/TI) hunt |
| `/malware` | Static triage and sandbox queue (CAPE/DRAKVUF when configured) |
| `/attack-coverage` | Detection ATT&CK coverage |
| `/models` | Model registry / drift views |
| `/detection-services` | Detection service health |
| `/detection/metrics` / `/detection/network` / `/detection/code-changes` | Modality consoles |
| `/data-health` | Ingestion / modality freshness |
| `/response-queue` | Human-gated SOAR approve/reject queue |
| `/security-profiles` | Security profile packs / coverage |

Related: `/assets`, `/attack`, `/admin`, `/triage`, `/cases`. Promote a detection incident into a TIP case with `POST /api/v1/detection-incidents/promote`.
