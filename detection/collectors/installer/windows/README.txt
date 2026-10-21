Black Onyx host collector Windows
===================================

Installs osqueryd + black-onyx-shipper (SHIPPER_SOURCES=osquery).

1. Install Python 3.10+ and ensure it is on PATH.
2. Open an elevated PowerShell in this folder.
3. Run:

   .\install.ps1 `
     -TenantId 'default' `
     -IngestKey 'your-ingest-key' `
     -GatewayUrl 'https://ingest.example.com' `
     -AssetId $env:COMPUTERNAME

Optional: -AssetRegistryUrl and -AssetRegistryKey to enroll the host.

The shipper runs as scheduled task BlackOnyxShipper at startup.
Ensure Windows Time (W32Time) syncs NTP before production use.
