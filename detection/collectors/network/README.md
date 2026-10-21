# Network sensor collectors (Zeek / Suricata / cloud flow logs → ingestion-gateway)
#
# Profiles:
#   zeek_http.toml: conn/dns/ssl JSON → POST /api/v1/ingest/zeek
#   suricata_http.toml: EVE alert JSON → POST /api/v1/ingest/suricata
#   aws_vpc_flow_logs.toml: S3-delivered VPC Flow Logs → POST /api/v1/ingest/network-flows
#   azure_nsg_flow_logs.toml: NSG Flow Logs v2 (via Event Hub) → POST /api/v1/ingest/network-flows
#   gcp_vpc_flow_logs.toml: VPC Flow Logs (via Pub/Sub) → POST /api/v1/ingest/network-flows
#
# Cloud profiles ship raw records; parsing lives in
# services/flow-processor/flow_processor/{aws,azure,gcp}_flow_adapter.py.
#
# Required env:
#   BLACK_ONYX_COLLECTOR_TENANT_ID, BLACK_ONYX_COLLECTOR_ASSET_ID, BLACK_ONYX_COLLECTOR_ID, BLACK_ONYX_COLLECTOR_SENSOR_ID, BLACK_ONYX_COLLECTOR_INGEST_KEY
# Optional:
#   BLACK_ONYX_COLLECTOR_GATEWAY_URL (default http://127.0.0.1:8080)
# Cloud-specific (see each profile's header comment):
#   AWS:   BLACK_ONYX_COLLECTOR_AWS_REGION, BLACK_ONYX_COLLECTOR_AWS_FLOWLOGS_SQS_URL
#   Azure: BLACK_ONYX_COLLECTOR_AZURE_EVENTHUB_NAMESPACE, BLACK_ONYX_COLLECTOR_AZURE_EVENTHUB_NAME, BLACK_ONYX_COLLECTOR_AZURE_EVENTHUB_CONNECTION_STRING
#   GCP:   BLACK_ONYX_COLLECTOR_GCP_PROJECT_ID, BLACK_ONYX_COLLECTOR_GCP_FLOWLOGS_SUBSCRIPTION
#
# See docs/deployment/network-sensors.md
