# Network sensors — Zeek + Suricata → Black Onyx

Ship Zeek protocol logs and Suricata EVE alerts into Black Onyx via the ingestion-gateway. Host clients use `localhost:19092` for Kafka; compose services use `redpanda:9092`. Prefer HTTP ingest with `X-API-Key` over direct Kafka producers.

## Topic / route mapping

| Sensor / source | Gateway route | Kafka topic | Downstream |
| --- | --- | --- | --- |
| NetFlow / IPFIX / enriched flows | `POST /api/v1/ingest/network-flows` | `network.raw` | `flow-processor` → `network.features` |
| Zeek `conn` / `dns` / `ssl` (any `zeek.*`) | `POST /api/v1/ingest/zeek` | `zeek.raw` | `flow-processor` Zeek adapter → features |
| Suricata EVE `alert` | `POST /api/v1/ingest/suricata` | `suricata.raw` | `ids-processor` → `findings.network` |
| DNS server logs | `POST /api/v1/ingest/dns` | `dns.raw` | DNS analytics (optional) |
| Firewall syslog/CEF | `POST /api/v1/ingest/firewall` | `firewall.raw` | `firewall-processor` |
| Selective PCAP excerpt metadata | `POST /api/v1/ingest/pcap-excerpt` | `pcap.meta` | Evidence refs (MinIO URI in payload) |

Always include envelope fields: `schema_version`, `event_id` (ULID), `event_type`, `tenant_id`, `occurred_at`, `ingested_at`, `source`, `asset`.

Default ingest key: `dev-ingest-key` (`X-API-Key`).

## Linux host / SPAN sensor (recommended)

1. Install Zeek and Suricata on Ubuntu/RHEL (SPAN/TAP NIC or host `af-packet`).
2. Enable Zeek JSON logs: `@load policy/tuning/json-logs`.
3. Enable Suricata `eve-log` with at least `alert` (optionally `dns`, `tls`, `flow`).
4. Run Vector with the profiles under `collectors/network/`:

```bash
export AA_TENANT_ID=tenant-demo
export AA_ASSET_ID=sensor-edge-01
export AA_COLLECTOR_ID=vector-nsm-01
export AA_SENSOR_ID=sensor-edge-01
export AA_INGEST_KEY=dev-ingest-key
export AA_GATEWAY_URL=http://127.0.0.1:8080

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
4. Inline `pcap_b64` or multipart file parts are **stripped** before Kafka publish — do not rely on the gateway for object storage.

Example payload URI: `s3://anomaly-pcap/tenant-demo/<excerpt_id>.pcap`.

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
