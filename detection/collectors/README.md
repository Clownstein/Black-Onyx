# Collectors

Thin host collectors for Black Onyx: **osquery** + **black-onyx-shipper** (`SHIPPER_SOURCES=osquery`)
ship telemetry to `ingestion-gateway`. This is not a commercial EDR replacement.

Download packages from **Operations → Assets** (Linux / Windows / macOS ZIPs), or build from this tree.

## Layout

| Path | Role |
| --- | --- |
| `osquery/packs/` | Scheduled query packs |
| `osquery/config/` | OS-specific osquery config |
| `installer/` | Linux / Windows / macOS install scripts (used by UI downloads) |
| `shipper/` | File shipper: osquery results, Wazuh `alerts.json`, Suricata `eve.json` |
| `vector/profiles/` | Optional Vector remap (prefer shipper for valid envelopes) |
| `network/` | Zeek / Suricata / cloud flow Vector profiles |
| `wazuh/` | Wazuh manager install, integratord hook, agent isolation AR |
| `suricata/` | Suricata sensor install (EVE alerts + shipper) |

## Host install (recommended)

```bash
# Linux example (root). Gateway loopback default: 127.0.0.1:18090
sudo BLACK_ONYX_COLLECTOR_TENANT_ID=default \
  BLACK_ONYX_COLLECTOR_INGEST_KEY="$API_KEYS" \
  BLACK_ONYX_COLLECTOR_GATEWAY_URL=http://127.0.0.1:18090 \
  BLACK_ONYX_COLLECTOR_ASSET_ID="$(hostname -s)" \
  ASSET_REGISTRY_URL=http://127.0.0.1:18081 \
  ASSET_REGISTRY_SERVICE_KEY="$ASSET_REGISTRY_SERVICE_KEY" \
  bash detection/collectors/installer/linux/install.sh
```

Windows: elevated `install.ps1`. macOS: `sudo ./install.sh`.

## NTP

All collectors and servers **must** sync time (NTP/Chrony/Windows Time). Clock skew breaks correlation windows and TI `valid_until`.

## Telemetry gaps

If an asset stops reporting, `host-state-processor` emits a `host_state_telemetry_gap`
finding on `findings.host-state`. Enable heartbeat monitoring with
`docker-compose.self-monitor.yml` (see that file). The overlay enrolls the Black Onyx
host in asset-registry; shipping still requires this native collector.

## Pipeline

```text
osquery scheduled queries → black-onyx-shipper → ingestion-gateway → host-state.raw
  → host-state-processor → host-state.features + findings.host-state
```

The shipper flattens osquery `columns` into the envelope payload so the
host-state normalizer receives real process/socket fields.
