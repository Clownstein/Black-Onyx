# Collectors

Thin host collectors for Black Onyx: **osquery** + **Vector** ship telemetry to `ingestion-gateway`.
This is not a commercial EDR replacement.

## Layout

| Path | Role |
| --- | --- |
| `osquery/packs/` | Scheduled query packs |
| `osquery/config/` | OS-specific osquery flags/config fragments |
| `vector/profiles/` | Ship configs → gateway HTTP or Kafka |
| `network/` | Zeek / Suricata Vector profiles → gateway |
| `installer/` | Linux / Windows / macOS install scripts |

## NTP

All collectors and servers **must** sync time (NTP/Chrony/Windows Time). Clock skew breaks correlation windows and TI `valid_until`.

## Telemetry gaps

If an asset stops reporting, `host-state-processor` emits a `host_state_telemetry_gap`
finding on `findings.host-state`, which flows through correlation-engine into an
incident like any other finding. See `docs/deployment/cross-platform-agents.md`.

Staleness is derived from the **enrolled** asset list in asset-registry, not from
observed traffic — so an agent that never starts is caught too, not just one that
goes quiet. Enable it with the self-monitor overlay:

```
docker compose -f docker-compose.yml -f docker-compose.platform.yml \
  -f docker-compose.detection-core.yml -f docker-compose.detection-apps.yml \
  -f docker-compose.self-monitor.yml up -d --build
```

That overlay enrolls the Black Onyx host itself (idempotently, via
`PUT /api/v1/assets/{asset_id}`) and switches on the heartbeat. Tuning knobs:
`SELF_MONITOR_TENANT_ID`, `SELF_MONITOR_ASSET_ID`, `SELF_MONITOR_STALE_AFTER_SECONDS`
(default 900s).

The overlay does **not** install a host collector — that stays native (see
`installer/`), because on Docker Desktop a containerized collector observes the
Linux VM rather than the actual Windows/macOS host.

## Known gap: osquery `columns` are not unwrapped

`vector/profiles/host_state_http.toml` re-tags osquery result lines but leaves the
osquery `columns` object nested. `host-state-processor`'s normalizer reads process
fields from the top level, so it picks up the pack query name (e.g. `processes`)
as the process name. Flatten `columns` into the envelope before shipping, or emit
already-normalized `host_state.*` events, which the normalizer accepts directly.
