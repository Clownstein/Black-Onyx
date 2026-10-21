Black Onyx host collector Linux
=================================

Installs osqueryd + black-onyx-shipper (SHIPPER_SOURCES=osquery).

1. Fill gateway values from your Black Onyx deployment (.env API_KEYS and
   BLACK_ONYX_DETECTION_TENANT). Gateway must be reachable from this host
   (loopback publish is 127.0.0.1:18090 by default when enabled).

2. Run as root:

   sudo BLACK_ONYX_COLLECTOR_TENANT_ID=default \
        BLACK_ONYX_COLLECTOR_INGEST_KEY='your-ingest-key' \
        BLACK_ONYX_COLLECTOR_GATEWAY_URL='http://127.0.0.1:18090' \
        BLACK_ONYX_COLLECTOR_ASSET_ID="$(hostname -s)" \
        ASSET_REGISTRY_URL='http://127.0.0.1:18081' \
        ASSET_REGISTRY_SERVICE_KEY='…' \
        ./install.sh

   Or without interactive sudo (Docker + nsenter into host systemd):

   BLACK_ONYX_COLLECTOR_TENANT_ID=… BLACK_ONYX_COLLECTOR_INGEST_KEY=… BLACK_ONYX_COLLECTOR_GATEWAY_URL=… ./install-via-docker.sh

3. Confirm:

   systemctl status black-onyx-shipper osqueryd
   journalctl -u black-onyx-shipper -f

NTP/chrony must be enabled so correlation windows stay valid.
