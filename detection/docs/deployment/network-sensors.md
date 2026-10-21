# Network sensors: Zeek + Suricata + cloud flow logs → Black Onyx

Ship Zeek protocol logs, Suricata EVE alerts, and cloud VPC flow logs into Black Onyx via the ingestion-gateway. Prefer HTTP ingest with `X-API-Key` over producing to Kafka directly. Host clients use `localhost:19092`; Compose services use `redpanda:9092`.

## Topic / route mapping

| Sensor / source | Gateway route | Kafka topic | Downstream |
| --- | --- | --- | --- |
| NetFlow / IPFIX / enriched flows | `POST /api/v1/ingest/network-flows` | `network.raw` | `flow-processor` → `network.features` |
| AWS VPC / Azure NSG / GCP VPC flow logs | `POST /api/v1/ingest/network-flows` | `network.raw` | `flow-processor` cloud adapters → features |
| Zeek `conn` / `dns` / `ssl` (any `zeek.*`) | `POST /api/v1/ingest/zeek` | `zeek.raw` | `flow-processor` Zeek adapter → features |
| Suricata EVE `alert` | `POST /api/v1/ingest/suricata` | `suricata.raw` | `ids-processor` → `findings.network` |
| DNS server logs | `POST /api/v1/ingest/dns` | `dns.raw` | DNS analytics (optional) |
| Firewall syslog/CEF | `POST /api/v1/ingest/firewall` | `firewall.raw` | `firewall-processor` |
| Selective PCAP excerpt metadata | `POST /api/v1/ingest/pcap-excerpt` | `pcap.meta` | Evidence refs (MinIO URI in payload) |

Cloud flow logs and passive NetFlow/IPFIX/Zeek share the same `POST /api/v1/ingest/network-flows` → `network.raw` → `flow-processor` path; the processor routes on `event_type` (`aws.vpc_flow_log` / `azure.nsg_flow_log` / `gcp.vpc_flow_log`) to the matching adapter.

Always include envelope fields: `schema_version`, `event_id` (ULID), `event_type`, `tenant_id`, `occurred_at`, `ingested_at`, `source`, `asset`.

Default ingest key: `dev-ingest-key` (`X-API-Key`).

## Linux host / SPAN sensor (recommended)

1. Install Zeek and Suricata on Ubuntu/RHEL (SPAN/TAP NIC or host `af-packet`).
2. Enable Zeek JSON logs: `@load policy/tuning/json-logs`.
3. Enable Suricata `eve-log` with at least `alert` (optionally `dns`, `tls`, `flow`).
4. Run Vector with the profiles under `collectors/network/`:

```bash
export BLACK_ONYX_COLLECTOR_TENANT_ID=tenant-demo
export BLACK_ONYX_COLLECTOR_ASSET_ID=sensor-edge-01
export BLACK_ONYX_COLLECTOR_ID=vector-nsm-01
export BLACK_ONYX_COLLECTOR_SENSOR_ID=sensor-edge-01
export BLACK_ONYX_COLLECTOR_INGEST_KEY=dev-ingest-key
export BLACK_ONYX_COLLECTOR_GATEWAY_URL=http://127.0.0.1:8080

vector --config collectors/network/zeek_http.toml
vector --config collectors/network/suricata_http.toml
```

Reference path:

```text
SPAN/host NIC
  → Zeek (conn/dns/ssl JSON)  → Vector → POST /ingest/zeek     → zeek.raw
  → Suricata (eve alert JSON) → Vector → POST /ingest/suricata → suricata.raw
                                                              → ids-processor → findings.network
```

Compose port for `ids-processor`: **8100** (8099 is `firewall-processor`).

## Cloud VPC flow logs (AWS / Azure / GCP)

Cloud flow logs need no passive sensor: Vector reads them from each provider's native export and posts to `/api/v1/ingest/network-flows`. Each profile ships the raw record mostly unparsed; the field parsing (and its pytest coverage) lives processor-side in `flow_processor/{aws,gcp,azure}_flow_adapter.py`, matching the Zeek/DNS collector/adapter split.

| Provider | Profile | Export path Vector reads | Adapter |
| --- | --- | --- | --- |
| AWS | `collectors/network/aws_vpc_flow_logs.toml` | VPC Flow Logs → S3, with an SQS notification queue (Vector `aws_s3` source) | `aws_flow_adapter.py` (default text format, 1:1) |
| Azure | `collectors/network/azure_nsg_flow_logs.toml` | NSG Flow Logs v2 → Diagnostic Settings/Event Grid → Event Hub (Vector `kafka` source, Event Hubs Kafka endpoint) | `azure_flow_adapter.py` (v2 JSON, 1:N fan-out: one blob holds many `flowTuples`) |
| GCP | `collectors/network/gcp_vpc_flow_logs.toml` | VPC Flow Logs → Cloud Logging sink → Pub/Sub (Vector `gcp_pubsub` source) | `gcp_flow_adapter.py` (Cloud Logging `LogEntry`, 1:1) |

Shared env is the same as the passive sensors (`BLACK_ONYX_COLLECTOR_TENANT_ID`, `BLACK_ONYX_COLLECTOR_ASSET_ID`, `BLACK_ONYX_COLLECTOR_ID`, `BLACK_ONYX_COLLECTOR_INGEST_KEY`, optional `BLACK_ONYX_COLLECTOR_GATEWAY_URL`), plus provider-specific settings documented in each profile's header:

- **AWS:** `BLACK_ONYX_COLLECTOR_AWS_REGION`, `BLACK_ONYX_COLLECTOR_AWS_FLOWLOGS_SQS_URL`
- **Azure:** `BLACK_ONYX_COLLECTOR_AZURE_EVENTHUB_NAMESPACE`, `BLACK_ONYX_COLLECTOR_AZURE_EVENTHUB_NAME`, `BLACK_ONYX_COLLECTOR_AZURE_EVENTHUB_CONNECTION_STRING`
- **GCP:** `BLACK_ONYX_COLLECTOR_GCP_PROJECT_ID`, `BLACK_ONYX_COLLECTOR_GCP_FLOWLOGS_SUBSCRIPTION`

```bash
vector --config collectors/network/aws_vpc_flow_logs.toml
vector --config collectors/network/azure_nsg_flow_logs.toml
vector --config collectors/network/gcp_vpc_flow_logs.toml
```

Kubernetes CNI/eBPF flow telemetry is not a supported collector. Cloud flows from the AWS, Azure, and GCP adapters use the same MITRE-tagged detectors as Zeek and NetFlow.

## Zeek field mapping (`zeek.conn`)

| Zeek | Platform / adapter |
| --- | --- |
| `id.orig_h` / hash | `src_ip` / `id_orig_h_hash` |
| `id.resp_h` / hash | `dst_ip` / `id_resp_h_hash` |
| `id.orig_p` / `id.resp_p` | `src_port` / `dst_port` |
| `proto` | `protocol` |
| `orig_bytes`+`resp_bytes` | `bytes` |
| `conn_state` | `connection_state` (`S0`/`REJ` → failed) |
| `ts` | `occurred_at` |
| `uid` | `zeek_uid` |
| `ssl` JA3/SNI | `tls.ja3` / `tls.sni` via `zeek.ssl` |
| `dns` query | `dns.query` / entropy via `zeek.dns` |

`flow-processor` adapts `event_type` values starting with `zeek.` through `flow_processor/zeek_adapter.py` into flow-shaped records, then runs TLS/DNS-aware detectors (rare JA3/JA4/SNI, DNS tunneling, beaconing, cross-host fan-out).

## Suricata sensor with the shipper (recommended)

`detection/collectors/suricata/install.sh` installs Suricata, writes EVE `alert` output (with ATT&CK metadata and community id) to `/var/log/suricata/eve.json`, binds `af-packet` to `SURICATA_INTERFACE`, and installs the Black Onyx shipper:

```bash
SURICATA_INTERFACE=eth1 sudo -E bash detection/collectors/suricata/install.sh
# then set BLACK_ONYX_COLLECTOR_TENANT_ID, BLACK_ONYX_COLLECTOR_GATEWAY_URL, BLACK_ONYX_COLLECTOR_INGEST_KEY, BLACK_ONYX_COLLECTOR_ASSET_ID, BLACK_ONYX_COLLECTOR_SENSOR_ID
sudo editor /etc/black-onyx-shipper/shipper.env && sudo systemctl restart black-onyx-shipper
```

The shipper posts each alert to `POST /api/v1/ingest/suricata` with a ULID derived from the source line, so retries resend identical events. Batches stay within the gateway's `MAX_BATCH_SIZE` / `MAX_BODY_BYTES` (`SHIPPER_GATEWAY_BATCH`, `SHIPPER_GATEWAY_MAX_BYTES`); an oversized batch is split, and the file position is saved only after the gateway accepts it. After log rotation the shipper finishes the rotated file (`SHIPPER_SURICATA_ROTATED_GLOB`) before following the new one.

The installer enables Suricata `stats` records every 30 seconds. The shipper sends a `host_state.agent_status` heartbeat for the sensor only while `eve.json` has been written within `SHIPPER_SENSOR_STALE_SECONDS` (default 600), so a stopped or wedged Suricata raises a telemetry-gap incident once the sensor is enrolled. When a Wazuh manager runs on the same host, the installer enables both sources; Wazuh alerts from Suricata rule groups are dropped there so one network alert is not filed twice.

`collectors/network/suricata_http.toml` remains a lab sketch: it stamps one static `event_id` per alert unless `BLACK_ONYX_COLLECTOR_EVENT_ID_OVERRIDE` is set, so use the shipper for real sensors.

## Suricata → findings

`ids-processor` maps Suricata severity **1–4** (1 = highest) to `severity_hint` / `calibrated_score`:

| Suricata | severity_hint | calibrated_score |
| --- | --- | --- |
| 1 | critical | 0.95 |
| 2 | high | 0.80 |
| 3 | medium | 0.55 |
| 4 | low | 0.30 |

Finding `context` includes `signature_id`, `signature`, `community_id`, and `asset_id`. MITRE tags from the event or alert metadata are preserved.

## Selective PCAP excerpt (Phase N3 start)

`POST /api/v1/ingest/pcap-excerpt` publishes **metadata only** to `pcap.meta`.

1. Capture ±N seconds / M packets on the sensor (tcpdump/dumpcap).
2. Upload the PCAP to MinIO (or S3-compatible store) with a short TTL.
3. POST an envelope whose payload includes at least `excerpt_id`, `sha256`, `uri`, `reason` (see `contracts/network/pcap_excerpt.schema.json`).
4. Inline `pcap_b64` or multipart file parts are **stripped** before Kafka publish; do not rely on the gateway for object storage.

Example payload URI: `s3://black-onyx-pcap/tenant-demo/<excerpt_id>.pcap`.

## Firewall / DNS (unchanged)

Firewall CEF/syslog → `/api/v1/ingest/firewall` → `firewall.raw`. DNS resolver logs → `/api/v1/ingest/dns` → `dns.raw`.

## Flow-processor detectors (MITRE-tagged)

| Detector | Techniques | Notes |
| --- | --- | --- |
| `new_external_peer` | T1071 | Novel external peer_hash |
| `port_scan_heuristic` | T1046 | High fan-out, low bytes |
| `failed_connection_burst` | T1046 | Failed ratio spike |
| `beaconing_heuristic` | T1071, T1573 | Periodic reconnects to same peer |
| `cross_host_external_ip` | T1071, T1102 | Same external peer across ≥2 assets |
| `rare_tls_fingerprint` | T1573, T1071 | Novel JA3/JA4/SNI |
| `dns_tunneling_heuristic` | T1071, T1048 | Long / high-entropy DNS queries |

## Security notes

- Never publish plaintext IPs from `flow-processor` features (hashed with `FLOW_PROCESSOR_IP_HASH_SALT`).
- Prefer hashed IPs in Zeek/Suricata contracts when possible.
- Keep PCAP excerpts purpose-limited with TTL + access audit; default is no continuous full-payload capture.
- Prefer TLS for Vector → gateway; use network ACLs between sensors and brokers.
