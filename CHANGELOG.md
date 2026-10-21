# Release notes

## 1.0.0 (September 2026)

First general release of Black Onyx: the threat-intelligence workspace, the detection plane, the Security Lab, and the Black Onyx 5B and Antares-1B models.

### Security and access control

- Security-tool requests use signed, short-lived actor assertions and durable,
  single-use approvals bound to the reviewed request.
- Tool execution uses structured arguments and isolated runner jobs. Read tools
  receive read-only workspaces, and agent workflows pause for approval before a
  non-read action.
- Detection BFF mutations use declared, schema-validated adapters with
  tenant-aware identity handling.
- Production Compose separates internal service traffic from explicitly
  configured egress and keeps data stores off published host ports.
- Network-dependent security tools ship disabled and are enabled only after an
  operator verifies per-job destination enforcement. Unsupported integrations
  return an explicit unavailable response rather than simulating a result.

### Administration and operations

- The administration API and UI provide settings metadata, including effective
  values, sources, consumers, and restart requirements.
- Compose and Helm deployment revisions support preview, approval, signed
  hand-off, health checks, and rollback.
- Backup retention and audit-event retention are configurable. Restore
  coordinates SQLite and Qdrant state with rollback support.
- Notification delivery uses a visible retrying outbox; deployments without a
  delivery provider report events as `logged-only`.

### Models and detection

- Model aliases reflect packages confirmed as loaded by serving replicas.
- Promotion and rollback verify signed packages and commit serving state only
  after replica confirmation.
- Training jobs use durable queues and fence stale workers before reserving
  model versions.
- Model-gateway canary routing uses confirmed package state and reports the
  expected and served versions.

### Deployment and configuration

- Correlation API access is disabled by default and requires a configured key
  and matching tenant identity.
- `RESPONSE_ORCHESTRATOR_API_KEY` authenticates the TIP BFF, response
  orchestrator, and integration hub to each other.
- Compose and Helm settings inventory includes production authentication
  requirements and secret metadata.
