# Security operations guide

## Required production settings

- Set `security.production: true`.
- Set an HTTPS `security.external_url`.
- Enable `security.secure_cookies`.
- Generate and retain `BLACK_ONYX_AUTH_SECRET` in a secret manager. The application requires a secret in every mode; there is no shared development fallback. Legacy `DEFENDERS_CHAT_AUTH_SECRET` is still accepted during rename transitions.
- Configure exact `allowed_hosts`, `allowed_origins`, and proxy CIDRs.
- Keep API documentation disabled unless a separately protected administrative deployment requires it.

Production validation rejects HTTP external URLs and insecure cookies. Forwarded headers are trusted only from configured proxy addresses.

## Browser and machine auth

- Session cookies: `blackonyx_session` (or `__Host-blackonyx_session` with secure cookies).
- CSRF cookie: `blackonyx_csrf`; unsafe browser methods send `X-CSRF-Token` and must pass origin checks.
- Connector push and webhook ingest may authenticate with machine tokens. CSRF/origin skip applies only when a machine token header is present (`X-Connector-Token`, `X-Webhook-Token`, or Bearer). Dual-mode endpoints must not weaken browser CSRF when those headers are absent.

## Secret handling

Do not store provider, SMTP, TAXII, connector, or authentication secrets in YAML, images, or source control. TAXII feed configuration stores `password_env`, not a password. Site credentials and runtime admin secrets are Fernet-encrypted at rest with domain-separated keys derived from the auth secret. The capability and system APIs deliberately omit sensitive paths and configuration values.

## Network controls

Qdrant and the application are private behind the production proxy network. Feed destinations require explicit host allowlisting and global DNS addresses. Each request connects to a validated resolved IP while retaining the original HTTPS SNI and Host values; every redirect is resolved and pinned again. This closes the DNS-rebinding gap between validation and connection. The supplied Caddy and Nginx examples terminate TLS and forward the original host and scheme.

Gallery iframe embedding of external sites requires deliberate CSP `frame-src` allowlisting; keep `frame-ancestors 'none'` on Black Onyx responses.

## Incident response

- Disable an account to invalidate all sessions immediately.
- Change a user's password or complete a reset to revoke their sessions.
- Rotate connector push tokens and webhook tokens if leaked.
- Rotate the global authentication secret only during a coordinated outage; it invalidates token hashes and encrypted MFA, runtime, and site-credential material.
- Preserve the state directory (or Continuity backup), Qdrant snapshot, proxy logs, and audit events before investigation.

## Release gates

Before production, run Python tests, frontend tests/build, Bandit, pip-audit, npm audit, secret scanning, CSP inspection, upload abuse tests, and Docker runtime acceptance. A dependency audit failure is a release blocker until reviewed.
