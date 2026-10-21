# Security

## Required production settings

- Set `security.production: true`.
- Set an HTTPS `security.external_url`.
- Enable `security.secure_cookies`.
- Generate and retain `BLACK_ONYX_AUTH_SECRET` in a secret manager. The application requires a secret in every mode; there is no shared development fallback.
- Configure exact `allowed_hosts`, `allowed_origins`, and proxy CIDRs.
- Keep API documentation disabled unless a separately protected administrative deployment requires it.

Production validation rejects HTTP external URLs and insecure cookies. Forwarded headers are trusted only from configured proxy addresses.

## Browser and machine auth

- Session cookies: `blackonyx_session` (or `__Host-blackonyx_session` with secure cookies).
- CSRF cookie: `blackonyx_csrf`; unsafe browser methods send `X-CSRF-Token` and must pass origin checks.
- Connector push and webhook ingest may authenticate with machine tokens. CSRF/origin skip applies only when a machine token header is present (`X-Connector-Token`, `X-Webhook-Token`, or Bearer). Dual-mode endpoints must not weaken browser CSRF when those headers are absent.

### MCP machine auth

Official MCP tool servers (`black-onyx-tools/`) authenticate to the TIP API as a machine principal, never with browser session cookies.

- Callers send `X-MCP-Service-Key` matching `BLACK_ONYX_MCP_SERVICE_KEY`.
- The TIP process maps that key to the active user named by `BLACK_ONYX_MCP_ACTOR_USER_ID`. The actor must be an active `admin` or `analyst`; viewers are rejected.
- Auth is fail-closed: missing key, missing actor, wrong key, inactive actor, or disallowed role yields `401` / no principal. Valid MCP auth skips CSRF and origin checks for that request only; RBAC still applies from the actor's role.
- Demo-shaped keys (`dev-`, `demo-`, `changeme`, `minioadmin`) are rejected unless `ALLOW_DEMO_KEYS` is explicitly enabled (`1` / `true` / `yes` / `on`). Do not enable that flag in production.

## Secret handling

Do not store provider, SMTP, TAXII, connector, or authentication secrets in YAML, images, or source control. TAXII feed configuration stores `password_env`, not a password. Site credentials and runtime admin secrets are Fernet-encrypted at rest with domain-separated keys derived from the auth secret. The capability and system APIs deliberately omit sensitive paths and configuration values.

## Network controls

Qdrant and the application are private behind the production proxy network. Feed destinations require explicit host allowlisting and global DNS addresses. Each request connects to a validated resolved IP while retaining the original HTTPS SNI and Host values; every redirect is resolved and pinned again. This closes the DNS-rebinding gap between validation and connection. The supplied Caddy and Nginx examples terminate TLS and forward the original host and scheme.

Gallery iframe embedding of external sites requires deliberate CSP `frame-src` allowlisting; keep `frame-ancestors 'none'` on Black Onyx responses.

## Security tools (gateway + runner + sandbox)

The security-tools stack catalogs 45 defensive MCP tools; gates and image
attestation determine which offline tools are available, and all network tools
remain unavailable until per-job egress is enforced. Browser traffic flows through
the BFF (`/api/v1/security/*`); the browser never talks to the security gateway or
runner directly.

### Architecture

```
Browser → BFF (/api/v1/security/*) → security-gateway → security-runner → ephemeral Docker container
```

- **BFF** signs a short-lived actor assertion (HMAC-SHA256 with `SECURITY_GATEWAY_KEY`,
  `iss=black-onyx-bff`, `aud=black-onyx-security-gateway`, `sub`, `role`, lifetime ≤ 15
  minutes) per request; no browser-held keys.
- **Security gateway** verifies that assertion (constant-time), binds each session
  workspace to the verified actor, runs the agent loop and dispatches tools.
- **Security runner** authenticates with `SECURITY_RUNNER_TOKEN`; runs each tool as a
  structured `argv` (never a shell, except the separately gated `Bash` tool) in an
  ephemeral, digest-pinned container with no network, dropped capabilities, a
  read-only root filesystem and resource limits. Read-only tools get a read-only
  workspace mount. Containers are removed after execution.
- Each session may run `SECURITY_RUNNER_MAX_JOBS_PER_SESSION` jobs at once, its
  workspace is capped by `SECURITY_RUNNER_WORKSPACE_QUOTA_BYTES`, and a running job
  can be cancelled by its owner (`POST /api/v1/security/tools/jobs/{job_id}/cancel`
  with `session_id`).
- Tools beyond the baseline image are enabled only after the runner's
  `/capabilities` probe (run in the same hardened, network-less sandbox) attests
  their binaries and Python modules in the digest-pinned image.

### Tool tiers and approval

Each tool's tier, availability, gate and real behavior are listed in
[SECURITY_TOOLS.md](SECURITY_TOOLS.md) (maintained against the gateway catalog).

Read-tier tools execute without approval. Every other tier needs a **durable,
single-use approval** from the gateway:

1. `POST /v1/tools/{tool}/preview` validates the call and returns a `preview_hash`
   binding actor, tool, normalized arguments, session, network profile,
   destinations, timeout and policy version.
2. `POST /v1/tools/{tool}/approve` with that preview returns an `approval_id`
   (expires after 300 s). Destructive, transaction and privileged-capture tiers
   require an administrator. Tiers listed in `SECURITY_TWO_PERSON_TIERS` must be
   approved by a *different* administrator (who passes `requester`).
3. The execution request carries `approval_id`; the gateway consumes it atomically
   and rejects replays, expired approvals and any argument change.

Model-supplied flags (`confirm`, `approve`, `approved_tools`) and UI checkboxes are
never approval. MCP tools whose arguments would publish, poll feeds or add
watchlist entries are refused for every role and must be done in the
authenticated app.

**Agent runs.** When the agent chooses a non-read tool, the run pauses and returns
`status=pending_approval`, a `run_id` and the pending call (with its
`preview_hash`). Approve it as above, then `POST /v1/agent/runs/{run_id}/resume`
with the `approval_id` (or `deny: true`). A paused run resumes once, only for its
owner, and expires after an hour.

### Tool gates (fail-closed)

Dangerous tools are disabled by default and must be explicitly enabled:

| Gate | Default | Tools affected |
| --- | --- | --- |
| `ENABLE_BASH_TOOL` | `false` | `Bash` |
| `ENABLE_HYDRA` | `false` | `hydra_brute` |
| `ENABLE_TCPDUMP` | `false` | `tcpdump_capture` |
| `ENABLE_CAST_SEND` | `false` | `cast_send` (blockchain broadcast) |
| `SQLMAP_EXPLOIT_MODE` | `false` | sqlmap exploit mode |

### Target policy and egress

By default, the runner starts every job with `network_mode=none`.  Network tools
(`nmap_scan`, `port_scan`, `nikto_scan`, `gobuster_dir`, `sqlmap_scan`,
`whois_lookup`, `cast_call`, `get_contract_storage`, `hydra_brute`) require the
digest-pinned firewall guard and `SECURITY_EGRESS_VERIFIED=true`. The default is
false. Each approval binds the tool-derived destination, bounded TCP ports, and
the exact IPv4 answers returned during preview. Keep the gate false until
independent packet-escape and lifecycle testing passes.

Offline jobs retain the read-only root filesystem, dropped capabilities,
resource limits, and cleanup. The runner and gateway do not install tools at
runtime; final executor images must be digest-pinned, scanned, and smoke-tested.

`shodan_search`, `tcpdump_capture`, `add_ioc_to_case`, and registered challenge
operations have bounded server-side adapters. Each remains unavailable until
its provider, actor assertion, persistent state, or separate capture guard is
configured and ready. Challenge submissions are text/JSON data, size-limited,
and never executed. `cast_send` is limited to a registered private Anvil lab;
the node must identify as Anvil, report chain ID 31337, and expose the approved
sender as an unlocked account. The Anvil node signs with its own test key; no
signing key enters the gateway or tool job. The feature remains disabled until
its image, profile, and independent egress checks pass. `generate_yara_rule`
generates source offline and compile-checks it only when the runner attests the
YARA Python module in the pinned sandbox image; otherwise the tool is unavailable.

The target settings below remain fail-closed:

- `ALLOW_PRIVATE_TARGETS=false`: blocks the `lab` network profile
- `ALLOW_PUBLIC_TARGETS=false`: blocks the `public` network profile
- `ALLOWED_TARGETS`: explicit comma-separated allowlist (gateway side)
- `SECURITY_EGRESS_NETWORK`: dedicated labeled bridge; setting it alone does
  not enable network tools
- `SECURITY_GUARD_IMAGE`: trusted firewall helper pinned by a repository digest
- `SECURITY_EGRESS_VERIFIED=false` and `SECURITY_CAPTURE_VERIFIED=false`:
  operator gates that stay off until their independent tests pass

Both private and public targeting remain unavailable until real egress
enforcement and escape tests pass.

### MCP tools in chat

The chat MCP orchestrator (`McpToolOrchestrator`) runs the same 63 tools (18 platform
+ 45 security) in a multi-turn agent loop. The loop enforces the same tier/approval
policy as direct tool execution. Tool results are treated as untrusted evidence.

## Incident response

- Disable an account to invalidate all sessions immediately.
- Change a user's password or complete a reset to revoke their sessions.
- Rotate connector push tokens and webhook tokens if leaked.
- Rotate the global authentication secret only during a coordinated outage; it invalidates token hashes and encrypted MFA, runtime, and site-credential material.
- Preserve the state directory (or Continuity backup), Qdrant snapshot, proxy logs, and audit events before investigation.

## Release gates

Before production, run Python tests, frontend tests/build, Bandit, pip-audit, npm audit, secret scanning, CSP inspection, upload abuse tests, and Docker runtime acceptance. A dependency audit failure is a release blocker until reviewed.
