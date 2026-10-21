# First-launch full platform (Windows). Mirrors scripts/bootstrap_full_stack.sh.
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $Root

if (-not (Test-Path .env)) {
  Copy-Item .env.example .env
  Write-Host "Created .env from .env.example"
}

function Ensure-Env([string]$Key, [string]$Value) {
  $lines = @()
  if (Test-Path .env) { $lines = Get-Content .env }
  $found = $false
  $out = foreach ($line in $lines) {
    if ($line -like "$Key=*") {
      $found = $true
      $current = $line.Substring($Key.Length + 1)
      if ([string]::IsNullOrWhiteSpace($current)) { "$Key=$Value" } else { $line }
    } else { $line }
  }
  if (-not $found) { $out = @($out) + "$Key=$Value" }
  # BOM-free UTF-8: Windows PowerShell's utf8 BOM would corrupt the first key for Compose.
  [System.IO.File]::WriteAllLines((Join-Path $Root ".env"), [string[]]$out, (New-Object System.Text.UTF8Encoding $false))
}

function Get-EnvValue([string]$Key) {
  $line = Get-Content .env | Where-Object { $_ -like "$Key=*" } | Select-Object -First 1
  if (-not $line) { return "" }
  return ($line -split "=", 2)[1]
}

function New-Hex([int]$Bytes = 32) {
  $buf = New-Object byte[] $Bytes
  [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($buf)
  return ([System.BitConverter]::ToString($buf) -replace "-", "").ToLower()
}

Ensure-Env "BLACK_ONYX_AUTH_SECRET" (New-Hex)
Ensure-Env "BLACK_ONYX_DETECTION_TENANT" "default"
Ensure-Env "SECURITY_GATEWAY_KEY" (New-Hex)
Ensure-Env "SECURITY_RUNNER_TOKEN" (New-Hex)
Ensure-Env "POSTGRES_PASSWORD" (New-Hex)
$PostgresPassword = Get-EnvValue "POSTGRES_PASSWORD"
Ensure-Env "BLACK_ONYX_ADMIN_EMAIL" "admin@example.com"
Ensure-Env "BLACK_ONYX_ADMIN_PASSWORD" (New-Hex)
# Detection service-to-service credentials (compose fails closed without them).
foreach ($Key in @(
  "INCIDENT_API_SERVICE_KEY", "ASSET_REGISTRY_SERVICE_KEY", "THREAT_INTEL_SERVICE_API_KEY",
  "INTEGRATION_HUB_API_KEY", "MALWARE_SERVICE_API_KEY", "NOTIFICATION_API_KEY", "NOTIFICATION_WEBHOOK_SECRET",
  "TRAINING_API_KEY", "TRAINING_ARTIFACT_SIGNING_KEY", "INFER_API_KEY", "MODEL_GATEWAY_API_KEY",
  "EMBEDDING_API_KEY", "CODE_ENRICHMENT_API_KEY", "PROFILE_EVALUATOR_API_KEY", "PROCESSOR_API_KEY",
  "RESPONSE_ORCHESTRATOR_API_KEY", "RESPONSE_ORCHESTRATOR_APPROVER_API_KEY")) {
  Ensure-Env $Key (New-Hex)
}
Ensure-Env "API_KEYS" (New-Hex)
Ensure-Env "BLACK_ONYX_COLLECTOR_INGEST_KEY" ((Get-EnvValue "API_KEYS") -split ",")[0]
Ensure-Env "MINIO_ROOT_USER" "blackonyx"
Ensure-Env "MINIO_ROOT_PASSWORD" (New-Hex)
# OpenSearch requires upper, lower, digit and symbol characters.
Ensure-Env "OPENSEARCH_INITIAL_ADMIN_PASSWORD" ("Bo1!" + (New-Hex))
Ensure-Env "ALLOW_PRIVATE_TARGETS" "true"
Ensure-Env "ALLOW_PUBLIC_TARGETS" "false"
Ensure-Env "SECURITY_EGRESS_VERIFIED" "true"
Ensure-Env "SECURITY_CAPTURE_VERIFIED" "true"
Ensure-Env "SECURITY_EGRESS_NETWORK" "blackonyx_sandbox_egress"
Ensure-Env "INGEST_GATEWAY_REMOTE_BIND" "127.0.0.1"
Ensure-Env "INGEST_GATEWAY_REMOTE_PORT" "18091"
Ensure-Env "ASSET_REGISTRY_REMOTE_BIND" "127.0.0.1"
Ensure-Env "ASSET_REGISTRY_REMOTE_PORT" "18082"
Ensure-Env "QDRANT_SECURITY__ALLOWED_HOSTS" '["web","localhost","127.0.0.1"]'
Ensure-Env "BLACK_ONYX_MISP_INTERNAL_HOSTS" "misp"
Ensure-Env "BLACK_ONYX_DATABASE_URL" "postgresql+psycopg://anomaly:${PostgresPassword}@postgres:5432/black_onyx"
Ensure-Env "SECURITY_GATEWAY_DATABASE_URL" "postgresql+psycopg://anomaly:${PostgresPassword}@postgres:5432/security_gateway"
Ensure-Env "SELF_MONITOR_TENANT_ID" "default"
Ensure-Env "SELF_MONITOR_HEARTBEAT" "true"
Ensure-Env "MISP_DB_PASSWORD" (New-Hex)
Ensure-Env "MISP_DB_ROOT_PASSWORD" (New-Hex)
Ensure-Env "MISP_ADMIN_EMAIL" (Get-EnvValue "BLACK_ONYX_ADMIN_EMAIL")
Ensure-Env "MISP_ADMIN_PASSPHRASE" (New-Hex)
Ensure-Env "SECURITY_LAB_PROFILES_JSON" '{"anvil":{"network":"blackonyx_anvil","cidrs":["10.88.0.0/24"],"ports":[80,8545]}}'
$SessionsRoot = Join-Path $Root ".security-sessions"
New-Item -ItemType Directory -Force -Path $SessionsRoot | Out-Null
Ensure-Env "SECURITY_SESSIONS_HOST_ROOT" $SessionsRoot

New-Item -ItemType Directory -Force -Path models\Black-Onyx-5B, models\tool-router | Out-Null

$MispSslDir = Join-Path $Root "data\misp-ssl"
New-Item -ItemType Directory -Force -Path $MispSslDir | Out-Null
$MispCert = Join-Path $MispSslDir "cert.pem"
$MispKey = Join-Path $MispSslDir "key.pem"
$MispDh = Join-Path $MispSslDir "dhparams.pem"
if (-not (Test-Path $MispCert) -or -not (Test-Path $MispKey)) {
  openssl req -x509 -nodes -newkey rsa:2048 `
    -keyout $MispKey -out $MispCert -days 3650 -subj "/CN=misp"
  if ($LASTEXITCODE -ne 0 -or -not (Test-Path $MispCert) -or -not (Test-Path $MispKey)) {
    throw "failed to generate data/misp-ssl certs required by docker-compose.misp.yml"
  }
}
if (-not (Test-Path $MispDh)) {
  openssl dhparam -out $MispDh 2048
  if ($LASTEXITCODE -ne 0 -or -not (Test-Path $MispDh)) {
    throw "failed to generate data/misp-ssl/dhparams.pem required by MISP nginx"
  }
}

$SandboxImage = Get-EnvValue "SECURITY_SANDBOX_IMAGE"
$GuardImage = Get-EnvValue "SECURITY_GUARD_IMAGE"
if ([string]::IsNullOrWhiteSpace($SandboxImage) -or [string]::IsNullOrWhiteSpace($GuardImage)) {
  Write-Host "Building security toolbox and guard (digest pin required by the runner)"
  if (Test-Path "services/security-runner/toolbox-build.env") {
    Get-Content "services/security-runner/toolbox-build.env" | ForEach-Object {
      if ($_ -match '^\s*([A-Za-z_][A-Za-z0-9_]*)=(.*)$') {
        Set-Item -Path "Env:$($matches[1])" -Value $matches[2]
      }
    }
  }
  docker build --pull=false -f services/security-runner/toolbox.Dockerfile `
    --build-arg "TOOLBOX_BASE_IMAGE=$env:TOOLBOX_BASE_IMAGE" `
    --build-arg "DEBIAN_SNAPSHOT=$env:DEBIAN_SNAPSHOT" `
    --build-arg "DEBIAN_SUITE=$env:TOOLBOX_DEBIAN_SUITE" `
    --build-arg "GOBUSTER_DEBIAN_VERSION=$env:GOBUSTER_DEBIAN_VERSION" `
    --build-arg "FOUNDRY_VERSION=$env:FOUNDRY_VERSION" `
    --build-arg "FOUNDRY_SHA256=$env:FOUNDRY_SHA256" `
    --build-arg "SOLC_DOWNLOAD_URL=$env:SOLC_DOWNLOAD_URL" `
    --build-arg "SOLC_SHA256=$env:SOLC_SHA256" `
    --build-arg "NIKTO_VERSION=$env:NIKTO_VERSION" `
    --build-arg "NIKTO_SHA256=$env:NIKTO_SHA256" `
    --build-arg "FILEBYTES_VERSION=$env:FILEBYTES_VERSION" `
    --build-arg "FILEBYTES_SHA256=$env:FILEBYTES_SHA256" `
    -t blackonyx-security-toolbox:bootstrap .
  docker build --pull=false -f services/security-runner/guard.Dockerfile `
    --build-arg "GUARD_BASE_IMAGE=$env:GUARD_BASE_IMAGE" `
    --build-arg "DEBIAN_SNAPSHOT=$env:DEBIAN_SNAPSHOT" `
    --build-arg "DEBIAN_SUITE=$env:GUARD_DEBIAN_SUITE" `
    -t blackonyx-security-guard:bootstrap .
  $ToolboxId = docker image inspect blackonyx-security-toolbox:bootstrap --format '{{.Id}}'
  $GuardId = docker image inspect blackonyx-security-guard:bootstrap --format '{{.Id}}'
  Ensure-Env "SECURITY_SANDBOX_IMAGE" "blackonyx-security-toolbox@$ToolboxId"
  Ensure-Env "SECURITY_GUARD_IMAGE" "blackonyx-security-guard@$GuardId"
}

# Dynamic detonation needs a real CAPEv2 lab reached via CAPE_URL. Without one
# the orchestrator stays not-ready and no dynamic findings are produced.
$CapeUrl = Get-EnvValue "CAPE_URL"
if (-not $CapeUrl) { Write-Warning "CAPE_URL is unset - dynamic malware detonation is disabled" }

$Infra = @(
  "-f", "docker-compose.yml",
  "-f", "docker-compose.platform.yml",
  "-f", "docker-compose.security-tools.yml"
)
$Full = @(
  "-f", "docker-compose.yml",
  "-f", "docker-compose.platform.yml",
  "-f", "docker-compose.detection-apps.yml",
  "-f", "docker-compose.security-tools.yml",
  "-f", "docker-compose.security-lab.yml",
  "-f", "docker-compose.misp.yml",
  "-f", "docker-compose.self-monitor.yml"
)

function Invoke-Checked([string]$What, [scriptblock]$Block) {
  & $Block
  if ($LASTEXITCODE -ne 0) { throw "$What failed (exit $LASTEXITCODE)" }
}

Invoke-Checked "build cli/security-gateway" { docker compose @Infra build cli security-gateway }
Invoke-Checked "start postgres" { docker compose @Infra up -d postgres }
# Database URLs carry the Postgres password: pass them by name, not on argv.
$env:ENSURE_DATABASE_URL = "postgresql+psycopg://anomaly:${PostgresPassword}@postgres:5432/anomaly"
docker compose @Infra run --rm --no-deps -e ENSURE_DATABASE_URL --entrypoint /app/.venv/bin/python cli `
  /app/scripts/ensure_postgres_databases.py
if ($LASTEXITCODE -ne 0) { throw "postgres preparation failed (exit $LASTEXITCODE)" }

$env:BLACK_ONYX_DATABASE_URL = Get-EnvValue "BLACK_ONYX_DATABASE_URL"
$env:SECURITY_GATEWAY_DATABASE_URL = Get-EnvValue "SECURITY_GATEWAY_DATABASE_URL"
docker compose @Infra run --rm --no-deps -e BLACK_ONYX_DATABASE_URL -e SECURITY_GATEWAY_DATABASE_URL `
  --entrypoint /app/.venv/bin/python cli `
  /app/scripts/migrate_sqlite_to_postgres.py `
  --state-dir /app/.checkpoints `
  --approval-db /app/security-state/approvals.db `
  --challenge-db /app/security-state/challenges.sqlite3
if ($LASTEXITCODE -ne 0) { throw "postgres preparation failed (exit $LASTEXITCODE)" }

Invoke-Checked "compose up" { docker compose @Full up -d --build }

# Load .env into this process so child tools (docker -e, python) see the values.
Get-Content .env | ForEach-Object {
  if ($_ -match '^\s*([A-Za-z_][A-Za-z0-9_]*)=(.*)$') { Set-Item -Path "Env:$($matches[1])" -Value $matches[2] }
}

if ($env:SKIP_ADMIN_BOOTSTRAP -ne "1") {
  # Password passes by name from the environment, never on the command line.
  docker compose -f docker-compose.yml run --rm -T -e BLACK_ONYX_ADMIN_PASSWORD cli `
    users bootstrap-admin --email $env:BLACK_ONYX_ADMIN_EMAIL --password-env BLACK_ONYX_ADMIN_PASSWORD
  if ($LASTEXITCODE -ne 0) { Write-Warning "Admin bootstrap skipped (an administrator may already exist)" }
}

if (-not $env:MISP_API_KEY) {
  Write-Host "Waiting for MISP to accept CLI commands to issue an API key"
  $MispKey = ""
  for ($i = 0; $i -lt 60 -and -not $MispKey; $i++) {
    $Out = docker compose @Full exec -T misp /var/www/MISP/app/Console/cake user change_authkey $env:MISP_ADMIN_EMAIL 2>$null
    if ($LASTEXITCODE -eq 0) {
      $Match = $Out | Select-String -Pattern ':\s*([A-Za-z0-9]{40})\s*$' | Select-Object -Last 1
      if ($Match) { $MispKey = $Match.Matches[0].Groups[1].Value }
    }
    if (-not $MispKey) { Start-Sleep -Seconds 10 }
  }
  if ($MispKey) {
    Ensure-Env "MISP_API_KEY" $MispKey
    $env:MISP_API_KEY = $MispKey
    Invoke-Checked "recreate web/malware-orchestrator" { docker compose @Full up -d web malware-orchestrator }
  } else {
    Write-Warning "Could not issue a MISP API key; set MISP_API_KEY in .env"
  }
}

Write-Host "Wazuh manager install is Linux-host only: sudo bash scripts/install_wazuh_host.sh"
Write-Host "Smoke checks"
$Failed = $false
function Test-Smoke([string]$Name, [scriptblock]$Check, [int]$Tries = 1) {
  for ($i = 0; $i -lt $Tries; $i++) {
    $ok = $false
    try { $ok = [bool](& $Check) } catch { $ok = $false }
    if ($ok) { Write-Host "ok   $Name"; return }
    Start-Sleep -Seconds 5
  }
  Write-Host "FAIL $Name" -ForegroundColor Red
  $script:Failed = $true
}
function Test-Http([string]$Url) {
  (Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 10).StatusCode -lt 400
}
function Test-InContainer([string]$Service, [string]$Url) {
  docker compose @Full exec -T $Service /usr/local/bin/python -c `
    "import sys, urllib.request; urllib.request.urlopen(sys.argv[1], timeout=10)" $Url | Out-Null
  $LASTEXITCODE -eq 0
}
$WebPort = if ($env:BLACK_ONYX_PORT) { $env:BLACK_ONYX_PORT } else { "8000" }
$IngestPort = if ($env:INGEST_GATEWAY_HOST_PORT) { $env:INGEST_GATEWAY_HOST_PORT } else { "18090" }
$RegistryPort = if ($env:ASSET_REGISTRY_HOST_PORT) { $env:ASSET_REGISTRY_HOST_PORT } else { "18081" }
$MispPort = if ($env:MISP_HOST_PORT) { $env:MISP_HOST_PORT } else { "8088" }

Test-Smoke "web API" { Test-Http "http://127.0.0.1:$WebPort/api/v1/health" } 36
Test-Smoke "ingestion gateway" { Test-Http "http://127.0.0.1:$IngestPort/health/live" } 24
Test-Smoke "asset registry" { Test-Http "http://127.0.0.1:$RegistryPort/health/live" } 24
Test-Smoke "security gateway" { Test-InContainer "security-gateway" "http://127.0.0.1:8000/health/ready" } 24
if ($CapeUrl) {
  Test-Smoke "malware orchestrator" { Test-InContainer "malware-orchestrator" "http://127.0.0.1:8113/health/ready" } 24
} else {
  Test-Smoke "malware orchestrator (detonation disabled)" { Test-InContainer "malware-orchestrator" "http://127.0.0.1:8113/health/live" } 24
}
Test-Smoke "MISP" { Test-Http "http://127.0.0.1:$MispPort/users/login" } 36
if ($CapeUrl) {
  Test-Smoke "CAPE detonation" { python scripts/smoke_malware_lab.py --require --base $CapeUrl; $LASTEXITCODE -eq 0 }
}
Test-Smoke "TIP config + collectors + security tools + MISP sync" {
  python scripts/bootstrap_post_deploy.py --tip-url "http://127.0.0.1:$WebPort"; $LASTEXITCODE -eq 0
}

Write-Host "Full stack compose finished (CAPE: $(if ($CapeUrl) { $CapeUrl } else { 'disabled' }))"
if ($Failed) {
  Write-Error "One or more smoke checks failed; see FAIL lines above"
  exit 1
}
