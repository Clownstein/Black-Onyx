# Sysmon → host-state mapping

Windows Sysmon events can feed `host-state.raw` (via Vector/Winlogbeat → ingestion-gateway). The host-state-processor normalizer maps common Event IDs into host-state event types.

## Event ID → host-state

| Sysmon EID | Sysmon name (typical) | host-state `event_type` | Notes |
| --- | --- | --- | --- |
| **1** | Process Create | `host_state.process_event` | Image, ParentImage, CommandLine, Hashes |
| **3** | Network Connection | `host_state.socket_snapshot` | Source/Dest IP+port, Protocol, Image |
| **10** | Process Access | `host_state.process_event` | Source/Target Image; treat as process/access signal |
| **11** | File Create | `host_state.process_event` | TargetFilename + Image (file create attributed to process) |
| **22** | DNS Query | `host_state.socket_snapshot` | QueryName + Image; network/DNS adjacency |

Implementation: `services/host-state-processor/host_state_processor/normalize.py` (EID heuristics on `EventID` / `event_id` / `eid`). Prefer shipping already-normalized `host_state.*` envelopes when possible.

## Recommended fields

| Field | Purpose |
| --- | --- |
| `tenant_id` / `asset_id` | Required for tenancy and correlation |
| `Image` / `ParentImage` | Process tree / parent-child rules |
| `CommandLine` | Suspicious interpreter detection |
| `Hashes` (`SHA256=…`) | TI hash match |
| `DestinationIp` / `DestinationPort` | New listen / egress context |
| `QueryName` (EID 22) | DNS hunting / TI domain match |

## Config tips

- Use a tuned SwiftOnSecurity-style Sysmon config; drop noisy Image paths.
- Do not disable Microsoft Defender to “make room” for Sysmon.
- Vector/Winlogbeat should stamp `AA_TENANT_ID` / `AA_ASSET_ID` (or equivalent) before gateway ingest.
- Lab: `HOST_STATE_PROCESSOR_ENABLE_KAFKA=false` + `POST /v1/process` before fleet rollout.

See also: `docs/deployment/cross-platform-agents.md`, `services/host-state-processor/AGENTS.md`.
