# Cross-platform agents (osquery + Vector)

## Goals

Ship host telemetry into Black Onyx without replacing commercial EDR.

| OS | Collector | Path |
| --- | --- | --- |
| Linux | osqueryd + Vector | `collectors/installer/linux/install.sh` |
| Windows | osqueryd + Vector | `collectors/installer/windows/install.ps1` |
| macOS | osqueryd + Vector | `collectors/installer/macos/install.sh` |

## Pipeline

```text
osquery scheduled queries → Vector remap → ingestion-gateway → host-state.raw
  → host-state-processor → host-state.features + findings.host-state
```

## Requirements

1. **NTP** on every host and server.
2. Set `AA_TENANT_ID`, `AA_ASSET_ID`, `AA_INGEST_KEY` (gateway API key).
3. Gateway must accept host-state ingest (HTTP path or Kafka produce to `host-state.raw`).
4. Prefer lab validation with `HOST_STATE_PROCESSOR_ENABLE_KAFKA=false` and `POST /v1/process` before fleet rollout.

## Sysmon (Windows)

See **[`sysmon.md`](sysmon.md)** for EID → host-state mapping (1, 3, 10, 11, 22). Use a tuned SwiftOnSecurity-style Sysmon config. Do not disable Microsoft Defender.

## Optional Wazuh

Wazuh agents may ship FIM/SCA/vuln events into the gateway as supplemental findings; Black Onyx remains the correlation brain.
