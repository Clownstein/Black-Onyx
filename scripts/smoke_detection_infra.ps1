# Detection-plane smoke: infra + ingest -> Kafka -> Postgres.
# From repo root, with Docker running:
#
#   docker compose -f docker-compose.yml -f docker-compose.platform.yml up -d postgres redpanda redpanda-init
#   docker compose -f docker-compose.yml -f docker-compose.platform.yml `
#     -f docker-compose.detection-core.yml up -d --build
#   powershell -File scripts/smoke_detection_infra.ps1
#
# The smoke uses the private Compose network. The optional lab-ports overlay is
# not required and detection APIs remain unexposed on the host.
#
#   powershell -File scripts/smoke_detection_infra.ps1 -RequireStack
#
# With -RequireStack, explicit ingest/incident/asset keys are required and any
# missing core service exits 1. CI supplies disposable non-demo values.

param(
  [switch]$RequireStack
)

$ErrorActionPreference = "Stop"

function Get-FirstCredential([string]$RawValue, [string]$Fallback) {
  $value = @($RawValue -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ }) | Select-Object -First 1
  if ($value) { return $value }
  return $Fallback
}

$key = Get-FirstCredential $env:API_KEYS "dev-ingest-key"
$incidentKey = Get-FirstCredential $env:INCIDENT_API_SERVICE_KEY "dev-service-key"
$assetKey = Get-FirstCredential $env:ASSET_REGISTRY_SERVICE_KEY "dev-service-key"

if ($RequireStack) {
  $missingSecrets = @()
  if (-not $env:API_KEYS -or $key -eq "dev-ingest-key") { $missingSecrets += "API_KEYS (non-demo)" }
  if (-not $env:INCIDENT_API_SERVICE_KEY -or $incidentKey -eq "dev-service-key") { $missingSecrets += "INCIDENT_API_SERVICE_KEY (non-demo)" }
  if (-not $env:ASSET_REGISTRY_SERVICE_KEY -or $assetKey -eq "dev-service-key") { $missingSecrets += "ASSET_REGISTRY_SERVICE_KEY (non-demo)" }
  if ($missingSecrets.Count -gt 0) {
    throw "Required smoke credentials are not set: $($missingSecrets -join ', ')"
  }
}

Write-Host "Checking Postgres..."
docker exec blackonyx-postgres pg_isready -U anomaly -d anomaly | Out-Host

Write-Host "Listing Kafka topics..."
docker exec blackonyx-redpanda rpk topic list --brokers redpanda:9092 | Select-Object -First 30

$ingest = docker ps -q -f "name=^/blackonyx-ingestion-gateway$"
$smoke = docker ps -q -f "name=^/blackonyx-smoke-consumer$"
$incident = docker ps -q -f "name=^/blackonyx-incident-api$"
$assets = docker ps -q -f "name=^/blackonyx-asset-registry$"
if (-not $ingest -or -not $smoke -or -not $incident -or -not $assets) {
  $missing = @()
  if (-not $ingest) { $missing += "blackonyx-ingestion-gateway" }
  if (-not $smoke) { $missing += "blackonyx-smoke-consumer" }
  if (-not $incident) { $missing += "blackonyx-incident-api" }
  if (-not $assets) { $missing += "blackonyx-asset-registry" }
  $msg = "Required detection stack containers missing: $($missing -join ', ')."
  if ($RequireStack) {
    Write-Error $msg
    Write-Host "Start detection-core, then re-run with -RequireStack:"
    Write-Host "  docker compose -f docker-compose.yml -f docker-compose.platform.yml -f docker-compose.detection-core.yml up -d --build"
    exit 1
  }
  Write-Host "Core apps not running - infra OK. Start detection-core for ingest smoke:"
  Write-Host "  docker compose -f docker-compose.yml -f docker-compose.platform.yml -f docker-compose.detection-core.yml up -d --build"
  exit 0
}

Write-Host "POST sample log event to ingestion-gateway..."
$now = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
$eventId = docker exec blackonyx-smoke-consumer python -c "from ulid import ULID; print(str(ULID()))"
$eventId = "$eventId".Trim()
if ($eventId -notmatch '^[0-7][0-9A-HJKMNP-TV-Z]{25}$') {
  throw "Smoke consumer did not generate a valid ULID"
}
$assetId = "host-smoke-$eventId"
$incidentId = "inc-smoke-$eventId"
$event = @{
  schema_version = "1.0"
  event_id       = $eventId
  event_type     = "log.raw"
  tenant_id      = "default"
  occurred_at    = $now
  ingested_at    = $now
  source         = @{ collector_id = "smoke"; source_type = "otel" }
  asset          = @{ asset_id = "host-smoke-1" }
  labels         = @{ smoke = "black-onyx" }
}
$payload = @{ events = @($event) } | ConvertTo-Json -Depth 6 -Compress
$encodedPayload = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($payload))

$ingestResult = docker exec `
  -e "BLACK_ONYX_SMOKE_PAYLOAD=$encodedPayload" `
  -e "BLACK_ONYX_SMOKE_KEY=$key" `
  blackonyx-smoke-consumer python -c "import base64,json,os,urllib.request; payload=base64.b64decode(os.environ['BLACK_ONYX_SMOKE_PAYLOAD']); req=urllib.request.Request('http://ingestion-gateway:8080/api/v1/ingest/logs',data=payload,headers={'X-API-Key':os.environ['BLACK_ONYX_SMOKE_KEY'],'Content-Type':'application/json'},method='POST'); response=urllib.request.urlopen(req,timeout=15); print(json.dumps({'status':response.status,'body':response.read().decode()}))"
$ingestResponse = $ingestResult | ConvertFrom-Json
if ([int]$ingestResponse.status -notin 200, 202) {
  throw "Ingestion gateway returned HTTP $($ingestResponse.status)"
}
Write-Host "Ingest status: $($ingestResponse.status)"

try {
  Write-Host "Creating and verifying a smoke asset in asset-registry..."
  $assetPayload = @{
    asset_id = $assetId
    asset_type = "host"
    name = "Black Onyx CI smoke asset"
    environment = "ci"
    criticality = 0.1
    tags = @{ smoke = "black-onyx" }
  } | ConvertTo-Json -Depth 5 -Compress
  $encodedAssetPayload = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($assetPayload))
  $assetResult = docker exec `
    -e "BLACK_ONYX_SMOKE_ASSET=$encodedAssetPayload" `
    -e "BLACK_ONYX_SMOKE_ASSET_KEY=$assetKey" `
    blackonyx-smoke-consumer python -c "import base64,json,os,urllib.request; payload=base64.b64decode(os.environ['BLACK_ONYX_SMOKE_ASSET']); req=urllib.request.Request('http://asset-registry:8081/api/v1/assets',data=payload,headers={'X-Tenant-Id':'default','X-Service-Key':os.environ['BLACK_ONYX_SMOKE_ASSET_KEY'],'Content-Type':'application/json'},method='POST'); response=urllib.request.urlopen(req,timeout=15); print(json.dumps({'status':response.status,'body':response.read().decode()}))"
  $assetResponse = $assetResult | ConvertFrom-Json
  if ([int]$assetResponse.status -ne 201) {
    throw "Asset registry returned HTTP $($assetResponse.status)"
  }
  if (($assetResponse.body | ConvertFrom-Json).asset_id -ne $assetId) {
    throw "Asset registry did not return the created smoke asset"
  }
  $assetReadResult = docker exec `
    -e "BLACK_ONYX_SMOKE_ASSET_KEY=$assetKey" `
    blackonyx-smoke-consumer python -c "import json,os,urllib.request; req=urllib.request.Request('http://asset-registry:8081/api/v1/assets/$assetId',headers={'X-Tenant-Id':'default','X-Service-Key':os.environ['BLACK_ONYX_SMOKE_ASSET_KEY']}); response=urllib.request.urlopen(req,timeout=15); print(json.dumps({'status':response.status,'body':response.read().decode()}))"
  $assetReadResponse = $assetReadResult | ConvertFrom-Json
  $assetReadBody = $assetReadResponse.body | ConvertFrom-Json
  if ([int]$assetReadResponse.status -ne 200 -or $assetReadBody.asset_id -ne $assetId -or $assetReadBody.tenant_id -ne "default") {
    throw "Asset registry read-back did not return the tenant-scoped smoke asset"
  }
  Write-Host "Asset registry write/read persistence: verified"

  Write-Host "Creating and reading back a smoke incident in incident-api..."
  $incidentPayload = @{
    incident_id = $incidentId
    title = "Black Onyx CI smoke incident"
    status = "open"
    severity = "low"
    risk_score = 0.1
    category = @("smoke")
    first_seen = $now
    last_seen = $now
    assets = @($assetId)
    services = @("ci-runtime-smoke")
    finding_ids = @()
    summary = "Disposable incident used to prove incident-api persistence."
    context = @{ smoke = "black-onyx" }
  } | ConvertTo-Json -Depth 6 -Compress
  $encodedIncidentPayload = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($incidentPayload))
  $incidentResult = docker exec `
    -e "BLACK_ONYX_SMOKE_INCIDENT=$encodedIncidentPayload" `
    -e "BLACK_ONYX_SMOKE_INCIDENT_KEY=$incidentKey" `
    blackonyx-smoke-consumer python -c "import base64,json,os,urllib.request; payload=base64.b64decode(os.environ['BLACK_ONYX_SMOKE_INCIDENT']); req=urllib.request.Request('http://incident-api:8083/api/v1/incidents',data=payload,headers={'X-Tenant-Id':'default','X-Service-Key':os.environ['BLACK_ONYX_SMOKE_INCIDENT_KEY'],'Content-Type':'application/json'},method='POST'); response=urllib.request.urlopen(req,timeout=15); print(json.dumps({'status':response.status,'body':response.read().decode()}))"
  $incidentResponse = $incidentResult | ConvertFrom-Json
  if ([int]$incidentResponse.status -ne 201 -or ($incidentResponse.body | ConvertFrom-Json).incident_id -ne $incidentId) {
    throw "Incident API did not create the smoke incident"
  }
  $incidentReadResult = docker exec `
    -e "BLACK_ONYX_SMOKE_INCIDENT_KEY=$incidentKey" `
    blackonyx-smoke-consumer python -c "import json,os,urllib.request; req=urllib.request.Request('http://incident-api:8083/api/v1/incidents/$incidentId',headers={'X-Tenant-Id':'default','X-Service-Key':os.environ['BLACK_ONYX_SMOKE_INCIDENT_KEY']}); response=urllib.request.urlopen(req,timeout=15); print(json.dumps({'status':response.status,'body':response.read().decode()}))"
  $incidentReadResponse = $incidentReadResult | ConvertFrom-Json
  $incidentReadBody = $incidentReadResponse.body | ConvertFrom-Json
  if ([int]$incidentReadResponse.status -ne 200 -or $incidentReadBody.incident_id -ne $incidentId -or $incidentReadBody.tenant_id -ne "default") {
    throw "Incident API read-back did not return the tenant-scoped smoke incident"
  }
  Write-Host "Incident API write/read persistence: verified"

  Write-Host "Waiting for exact event $eventId..."
  $stored = 0
  for ($attempt = 0; $attempt -lt 20; $attempt++) {
    Start-Sleep -Seconds 1
    $stored = docker exec blackonyx-postgres psql -U anomaly -d smoke -At -c "SELECT COUNT(*) FROM ingested_events WHERE tenant_id='default' AND event_id='$eventId';"
    $stored = [int]("$stored".Trim())
    if ($stored -eq 1) { break }
  }
  if ($stored -ne 1) {
    throw "Kafka smoke event was not persisted within 20 seconds"
  }
  Write-Host "Kafka/Postgres event persistence: verified"

  Write-Host "Incident API live:"
  docker exec blackonyx-incident-api python -c "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8083/health/live',timeout=10).read().decode())"
} finally {
  docker exec blackonyx-postgres psql -U anomaly -d smoke -c "DELETE FROM ingested_events WHERE tenant_id='default' AND event_id='$eventId';" | Out-Null
  docker exec blackonyx-postgres psql -U anomaly -d incident_api -c "DELETE FROM incidents WHERE tenant_id='default' AND incident_id='$incidentId';" | Out-Null
  try {
    docker exec `
      -e "BLACK_ONYX_SMOKE_ASSET_KEY=$assetKey" `
      blackonyx-smoke-consumer python -c "import os,urllib.request; req=urllib.request.Request('http://asset-registry:8081/api/v1/assets/$assetId',headers={'X-Tenant-Id':'default','X-Service-Key':os.environ['BLACK_ONYX_SMOKE_ASSET_KEY']},method='DELETE'); urllib.request.urlopen(req,timeout=15).read()" | Out-Null
  } catch {
    Write-Warning "Unable to remove smoke asset ${assetId}: $($_.Exception.Message)"
  }
}

Write-Host "OK - detection smoke complete."
