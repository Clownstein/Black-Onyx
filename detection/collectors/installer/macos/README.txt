Black Onyx host collector macOS
=================================

Installs osqueryd + black-onyx-shipper (SHIPPER_SOURCES=osquery).

1. Install osquery if needed: brew install --cask osquery
2. Run:

   sudo BLACK_ONYX_COLLECTOR_TENANT_ID=default \
        BLACK_ONYX_COLLECTOR_INGEST_KEY='your-ingest-key' \
        BLACK_ONYX_COLLECTOR_GATEWAY_URL='https://ingest.example.com' \
        BLACK_ONYX_COLLECTOR_ASSET_ID="$(scutil --get LocalHostName)" \
        ./install.sh

LaunchDaemon: com.blackonyx.shipper
Enable automatic time sync before production use.
