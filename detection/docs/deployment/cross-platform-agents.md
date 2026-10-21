# Host collectors (osquery, Vector, Wazuh)

Ship host telemetry into Black Onyx without replacing a commercial EDR.

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
2. Set `BLACK_ONYX_COLLECTOR_TENANT_ID`, `BLACK_ONYX_COLLECTOR_ASSET_ID`, `BLACK_ONYX_COLLECTOR_INGEST_KEY` (gateway API key).
3. Gateway must accept host-state ingest (HTTP path or Kafka produce to `host-state.raw`).
4. Prefer lab validation with `HOST_STATE_PROCESSOR_ENABLE_KAFKA=false` and `POST /v1/process` before fleet rollout.

## Sysmon (Windows)

See **[`sysmon.md`](sysmon.md)** for EID → host-state mapping (1, 3, 10, 11, 22). Use a tuned SwiftOnSecurity-style Sysmon config. Do not disable Microsoft Defender.

## Wazuh (alternative to osquery + Vector)

Install stock Wazuh agents (Linux packages, Windows MSI) pointed at your own Wazuh manager. Black Onyx does not speak the agent protocol and does not ship the manager, indexer, or dashboard. On the manager, run `detection/collectors/wazuh/install-manager.sh`; it installs the shipper (`detection/collectors/shipper/`) as `black-onyx-shipper.service`.

```text
Wazuh agents → manager alerts.json → shipper
  ├─ level ≥ WAZUH_MIN_LEVEL → POST /api/v1/connectors/{id}/push   (TIP triage, cases, analytics)
  ├─ Sysmon / auditd / logon  → POST /api/v1/ingest/host-state     (host-state rules → incidents)
  └─ every 300s per agent     → host_state.agent_status heartbeat  (telemetry-gap incidents)
```

1. In **Detections**, add a connector of type **Wazuh**. Base URL is the Wazuh indexer. A private hostname is accepted only when listed in `connectors.allowed_hosts`, and such a connector is push-only; indexer poll requires public HTTPS plus `username` / `password` credential env names.
2. **Issue push token** on that connector and put the id and token in `/etc/black-onyx-shipper/shipper.env` (`BLACK_ONYX_CONNECTOR_ID`, `BLACK_ONYX_CONNECTOR_TOKEN`) with the gateway URL, ingest key, and tenant.
3. Optional: set `ASSET_REGISTRY_URL` / `ASSET_REGISTRY_SERVICE_KEY` so each agent is enrolled once as `wazuh:<agent_id>` (existing assets are never overwritten; enrollment runs in the background so it never stalls shipping). Set `WAZUH_API_URL` / `WAZUH_API_USER` / `WAZUH_API_PASSWORD` when you enable heartbeats: without the API, heartbeats cover only agents that alerted recently, and a quiet but healthy agent can raise a false telemetry-gap incident. Add the tenant to `HOST_STATE_PROCESSOR_HEARTBEAT_TENANT_IDS` with `docker-compose.self-monitor.yml`.
4. `systemctl restart black-onyx-shipper`.

Connector detections and host-state findings share the asset id `wazuh:<agent_id>`, so triage, assets, and incidents point at the same host. Wazuh alerts in the `suricata` / `ids` / `eve` rule groups are dropped by the shipper; Suricata is ingested only from `eve.json` (see `network-sensors.md`).

Prefer the integratord hook instead of shipper push? Run `WITH_INTEGRATOR=true install-manager.sh`, add the block from `detection/collectors/wazuh/ossec.conf.snippet.xml`, and the installer sets `SHIPPER_WAZUH_PUSH=false` so alerts are not pushed twice. The shipper still sends host-state and heartbeats.

### Isolation through Wazuh active response

The `isolate-host` playbook stays human-approved and dry-run by default. For live runs set `EDR_PROVIDER=wazuh` on integration-hub (or `RESPONSE_ORCHESTRATOR_EDR_PROVIDER=wazuh` on response-orchestrator) with `WAZUH_API_URL`, `WAZUH_API_USER`, `WAZUH_API_PASSWORD`, and optionally `WAZUH_API_CA_FILE` and `WAZUH_ISOLATION_ALLOW` (comma-separated jump hosts that stay reachable). The adapter resolves `wazuh:<agent_id>`, checks the agent's platform, and dispatches `!black-onyx-isolate` (Linux) or `!black-onyx-isolate.cmd` (Windows Firewall). Install those scripts on agents with `install-agent-ar.sh` / `install-agent-ar.ps1`. `WAZUH_ISOLATION_ALLOW` entries must be IP addresses or CIDRs, and the request reason is reduced to plain text before it reaches the agent.

Both scripts allow the Wazuh manager from the agent's `ossec.conf`, refuse to isolate when that address cannot be resolved, restore the previous firewall state if any step fails, and lift isolation automatically after `ttl_minutes` (a new isolation replaces the pending restore). Linux blocks IPv4 and IPv6 (when `ip6tables` exists) on INPUT, OUTPUT and FORWARD, so containers are isolated too; rules and the restore timer do not survive a reboot, so a rebooted host comes back un-isolated. Windows refuses to isolate when Group Policy firewall settings or policy allow rules would override local isolation.

The Response queue asks for the target asset when a playbook acts on one, and the BFF rejects an `asset_id` that is not one of the incident's assets.
