# Install osquery + Vector profile for Black Onyx (Windows). Run elevated.
param(
  [string]$TenantId = $env:AA_TENANT_ID,
  [string]$AssetId = $env:AA_ASSET_ID,
  [string]$IngestKey = $env:AA_INGEST_KEY
)
if (-not $TenantId) { $TenantId = "tenant-demo" }
if (-not $AssetId) { $AssetId = $env:COMPUTERNAME }
if (-not $IngestKey) { $IngestKey = "dev-ingest-key" }

Write-Host "Installing osquery (requires elevated shell)…"
$installed = $false
if (Get-Command winget -ErrorAction SilentlyContinue) {
  try {
    winget install --id osquery.osquery --silent --accept-package-agreements --accept-source-agreements
    $installed = $true
  } catch {
    Write-Host "winget install failed: $_"
  }
} elseif (Get-Command choco -ErrorAction SilentlyContinue) {
  try {
    choco install osquery -y
    $installed = $true
  } catch {
    Write-Host "choco install failed: $_"
  }
}
if (-not $installed) {
  Write-Host "Install osquery manually: https://osquery.io/downloads"
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$root = Resolve-Path (Join-Path $scriptDir "..\..")
$osqueryDir = "$env:ProgramFiles\osquery"
New-Item -ItemType Directory -Force -Path "$osqueryDir\packs" | Out-Null
try {
  Copy-Item (Join-Path $root "osquery\packs\incident_response.conf") "$osqueryDir\packs\" -Force
  Copy-Item (Join-Path $root "osquery\config\windows.conf") "$osqueryDir\osquery.conf" -Force
} catch {
  Write-Host "Could not copy osquery config (install osquery first): $_"
}

Write-Host "Set AA_TENANT_ID=$TenantId AA_ASSET_ID=$AssetId AA_INGEST_KEY=(secret)"
Write-Host "Ship results with Vector profile collectors\vector\profiles\host_state_http.toml"
Write-Host "Ensure Windows Time (W32Time) is syncing NTP before production use."
