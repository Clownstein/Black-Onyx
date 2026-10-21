# Install osquery + Black Onyx shipper on Windows. Run elevated PowerShell.
# Works from the repo tree or from a downloaded collector package ZIP.
#
# Required: BLACK_ONYX_COLLECTOR_TENANT_ID / TenantId, BLACK_ONYX_COLLECTOR_INGEST_KEY / IngestKey, BLACK_ONYX_COLLECTOR_GATEWAY_URL / GatewayUrl
param(
  [string]$TenantId = $env:BLACK_ONYX_COLLECTOR_TENANT_ID,
  [string]$AssetId = $env:BLACK_ONYX_COLLECTOR_ASSET_ID,
  [string]$IngestKey = $env:BLACK_ONYX_COLLECTOR_INGEST_KEY,
  [string]$GatewayUrl = $env:BLACK_ONYX_COLLECTOR_GATEWAY_URL,
  [string]$CollectorId = $env:BLACK_ONYX_COLLECTOR_ID,
  [string]$Hostname = $env:BLACK_ONYX_COLLECTOR_HOSTNAME,
  [string]$AssetRegistryUrl = $env:ASSET_REGISTRY_URL,
  [string]$AssetRegistryKey = $env:ASSET_REGISTRY_SERVICE_KEY
)

$ErrorActionPreference = "Stop"
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw "Run this script from an elevated PowerShell session."
}

if (-not $AssetId) { $AssetId = $env:COMPUTERNAME }
if (-not $Hostname) { $Hostname = $AssetId }
if (-not $CollectorId) { $CollectorId = "osquery-$AssetId" }
if (-not $TenantId -or -not $IngestKey -or -not $GatewayUrl) {
  throw "TenantId/BLACK_ONYX_COLLECTOR_TENANT_ID, IngestKey/BLACK_ONYX_COLLECTOR_INGEST_KEY, and GatewayUrl/BLACK_ONYX_COLLECTOR_GATEWAY_URL are required"
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if ((Test-Path (Join-Path $scriptDir "osquery")) -and (Test-Path (Join-Path $scriptDir "shipper"))) {
  $pkgRoot = $scriptDir
} elseif ((Test-Path (Join-Path $scriptDir "..\..\osquery")) -and (Test-Path (Join-Path $scriptDir "..\..\shipper"))) {
  $pkgRoot = (Resolve-Path (Join-Path $scriptDir "..\..")).Path
} else {
  throw "Cannot locate collector package root (osquery\ + shipper\)"
}

Write-Host "Installing osquery…"
$installed = $false
if (Get-Command winget -ErrorAction SilentlyContinue) {
  try {
    winget install --id osquery.osquery --silent --accept-package-agreements --accept-source-agreements
    $installed = $true
  } catch {
    Write-Host "winget install failed: $_"
  }
}
if (-not $installed -and (Get-Command choco -ErrorAction SilentlyContinue)) {
  try {
    choco install osquery -y
    $installed = $true
  } catch {
    Write-Host "choco install failed: $_"
  }
}
if (-not (Get-Command osqueryd -ErrorAction SilentlyContinue) -and -not (Test-Path "$env:ProgramFiles\osquery\osqueryd\osqueryd.exe")) {
  Write-Host "Install osquery manually: https://osquery.io/downloads/official"
  throw "osqueryd not found after install attempt"
}

$osqueryDir = "$env:ProgramFiles\osquery"
New-Item -ItemType Directory -Force -Path "$osqueryDir\packs" | Out-Null
New-Item -ItemType Directory -Force -Path "$osqueryDir\log" | Out-Null
Copy-Item (Join-Path $pkgRoot "osquery\packs\incident_response.conf") "$osqueryDir\packs\" -Force
Copy-Item (Join-Path $pkgRoot "osquery\config\windows.conf") "$osqueryDir\osquery.conf" -Force
@"
--config_path=$osqueryDir\osquery.conf
--logger_plugin=filesystem
--logger_path=$osqueryDir\log
--disable_logging=false
--force=true
"@ | Set-Content -Path "$osqueryDir\osquery.flags" -Encoding ascii

$svc = Get-Service -Name osqueryd -ErrorAction SilentlyContinue
if ($svc) {
  Restart-Service osqueryd -Force -ErrorAction SilentlyContinue
  Start-Service osqueryd -ErrorAction SilentlyContinue
} else {
  & "$osqueryDir\osqueryd\osqueryd.exe" --install --flagfile="$osqueryDir\osquery.flags"
  Start-Service osqueryd -ErrorAction SilentlyContinue
}

$installDir = "C:\Program Files\Black Onyx\shipper"
$configDir = "C:\ProgramData\Black Onyx\shipper"
New-Item -ItemType Directory -Force -Path $installDir | Out-Null
New-Item -ItemType Directory -Force -Path $configDir | Out-Null
# shipper.env holds the ingest key: SYSTEM + Administrators only, no inheritance
# (SIDs keep this working on localized Windows).
& icacls.exe $configDir /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Failed to restrict ACL on $configDir" }
Copy-Item (Join-Path $pkgRoot "shipper\black_onyx_shipper.py") "$installDir\black_onyx_shipper.py" -Force

$resultsLog = "$osqueryDir\log\osqueryd.results.log"
$envPath = Join-Path $configDir "shipper.env"
@"
SHIPPER_SOURCES=osquery
BLACK_ONYX_COLLECTOR_TENANT_ID=$TenantId
BLACK_ONYX_COLLECTOR_GATEWAY_URL=$GatewayUrl
BLACK_ONYX_COLLECTOR_INGEST_KEY=$IngestKey
BLACK_ONYX_COLLECTOR_ID=$CollectorId
BLACK_ONYX_COLLECTOR_ASSET_ID=$AssetId
BLACK_ONYX_COLLECTOR_HOSTNAME=$Hostname
BLACK_ONYX_COLLECTOR_OS_FAMILY=windows
OSQUERY_RESULTS_FILE=$resultsLog
SHIPPER_START_AT=beginning
SHIPPER_HEARTBEAT_SECONDS=300
SHIPPER_STATE_FILE=$configDir\state.json
ASSET_REGISTRY_URL=$AssetRegistryUrl
ASSET_REGISTRY_SERVICE_KEY=$AssetRegistryKey
BLACK_ONYX_COLLECTOR_ENVIRONMENT=production
BLACK_ONYX_COLLECTOR_ASSET_CRITICALITY=0.5
"@ | Set-Content -Path $envPath -Encoding ascii

$pythonCmd = Get-Command python -ErrorAction SilentlyContinue
if (-not $pythonCmd) { $pythonCmd = Get-Command python3 -ErrorAction SilentlyContinue }
if (-not $pythonCmd) { throw "Python 3.10+ is required on PATH" }
$python = $pythonCmd.Source

$taskName = "BlackOnyxShipper"
$action = New-ScheduledTaskAction -Execute $python -Argument "`"$installDir\black_onyx_shipper.py`"" -WorkingDirectory $installDir
$trigger = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero)
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Force | Out-Null

# Load env for the task via a wrapper so secrets stay out of the task XML arguments.
$wrapper = Join-Path $installDir "run_shipper.cmd"
@"
@echo off
for /f "usebackq tokens=1,* delims==" %%A in ("$envPath") do set "%%A=%%B"
"$python" "$installDir\black_onyx_shipper.py"
"@ | Set-Content -Path $wrapper -Encoding ascii
$action2 = New-ScheduledTaskAction -Execute $wrapper
Set-ScheduledTask -TaskName $taskName -Action $action2 | Out-Null
Start-ScheduledTask -TaskName $taskName

$osq = Get-Service -Name osqueryd -ErrorAction SilentlyContinue
if (-not $osq) { throw "osqueryd service is not installed" }
$osq.WaitForStatus("Running", (New-TimeSpan -Seconds 30))
Start-Sleep -Seconds 5
$taskState = (Get-ScheduledTask -TaskName $taskName).State
if ($taskState -ne "Running") {
  $last = (Get-ScheduledTaskInfo -TaskName $taskName).LastTaskResult
  throw "BlackOnyxShipper task is $taskState (last result $last); check $envPath and Python"
}

Write-Host "Windows collector installed."
Write-Host "  asset_id=$AssetId tenant=$TenantId gateway=$GatewayUrl"
Write-Host "  task=$taskName env=$envPath"
Write-Host "Ensure Windows Time (W32Time) is syncing NTP before production use."
