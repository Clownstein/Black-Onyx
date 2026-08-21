# Network sensor collectors (Zeek / Suricata / cloud flow logs → ingestion-gateway)
#
# Profiles:
#   zeek_http.toml           — conn/dns/ssl JSON → POST /api/v1/ingest/zeek
#   suricata_http.toml       — EVE alert JSON → POST /api/v1/ingest/suricata
#   aws_vpc_flow_logs.toml   — S3-delivered VPC Flow Logs → POST /api/v1/ingest/network-flows
#   azure_nsg_flow_logs.toml — NSG Flow Logs v2 (via Event Hub) → POST /api/v1/ingest/network-flows
#   gcp_vpc_flow_logs.toml   — VPC Flow Logs (via Pub/Sub) → POST /api/v1/ingest/network-flows
#
# Cloud profiles ship raw records; parsing lives in
# services/flow-processor/flow_processor/{aws,azure,gcp}_flow_adapter.py.
#
# Required env:
#   AA_TENANT_ID, AA_ASSET_ID, AA_COLLECTOR_ID, AA_SENSOR_ID, AA_INGEST_KEY
# Optional:
#   AA_GATEWAY_URL (default http://127.0.0.1:8080)
# Cloud-specific (see each profile's header comment):
#   AWS:   AA_AWS_REGION, AA_AWS_FLOWLOGS_SQS_URL
#   Azure: AA_AZURE_EVENTHUB_NAMESPACE, AA_AZURE_EVENTHUB_NAME, AA_AZURE_EVENTHUB_CONNECTION_STRING
#   GCP:   AA_GCP_PROJECT_ID, AA_GCP_FLOWLOGS_SUBSCRIPTION
#
# See docs/deployment/network-sensors.md
