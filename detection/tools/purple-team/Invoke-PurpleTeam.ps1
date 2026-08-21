# Purple-team harness entrypoint.
# From repo root:
#   powershell -File detection/tools/purple-team/Invoke-PurpleTeam.ps1 -DryRun
#   $env:ATOMIC_RED_TEAM_PATH = "C:\tools\atomic-red-team"
#   powershell -File detection/tools/purple-team/Invoke-PurpleTeam.ps1

[CmdletBinding()]
param(
  [switch]$DryRun,
  [string]$AtomicPath = $env:ATOMIC_RED_TEAM_PATH,
  [string]$ExpectedMap = "",
  [string]$FindingsPath = "",
  [string]$TenantId = "",
  [string]$WindowStart = "",
  [string]$WindowEnd = "",
  [string]$ReportPath = ""
)

$ErrorActionPreference = "Stop"

$here = $PSScriptRoot
$scorer = Join-Path $here "score_purple_team.py"
if (-not $ExpectedMap) {
  $ExpectedMap = Join-Path $here "expected_findings.json"
}
if (-not (Test-Path $ExpectedMap)) {
  throw "expected_findings.json not found at $ExpectedMap"
}
$scoreValues = @($FindingsPath, $WindowStart, $WindowEnd, $ReportPath)
$scoreRequested = ($scoreValues | Where-Object { $_ }).Count -gt 0
if ($scoreRequested -and (-not $FindingsPath -or -not $WindowStart -or -not $WindowEnd -or -not $ReportPath)) {
  throw "Scoring requires -FindingsPath, -WindowStart, -WindowEnd, and -ReportPath."
}
if ($DryRun -and $scoreRequested) {
  throw "-DryRun cannot be combined with scoring arguments."
}

$map = Get-Content -Raw -Path $ExpectedMap | ConvertFrom-Json
Write-Host "Purple-team expected findings map ($($map.techniques.Count) techniques):"
foreach ($t in $map.techniques) {
  $types = ($t.expected_finding_types -join ", ")
  Write-Host ("  {0} ({1}) -> {2}" -f $t.technique_id, $t.name, $types)
}

Write-Host ""
Write-Host "Stack presence probes (container presence only - not health or SLO proof):"
$placeholders = @(
  @{ Name = "postgres"; Filter = "blackonyx-postgres" },
  @{ Name = "redpanda"; Filter = "blackonyx-redpanda" },
  @{ Name = "ingestion-gateway"; Filter = "blackonyx-ingestion-gateway" },
  @{ Name = "incident-api"; Filter = "blackonyx-incident-api" }
)
foreach ($p in $placeholders) {
  $id = $null
  try {
    $id = docker ps -q -f "name=$($p.Filter)" 2>$null
  } catch {
    $id = $null
  }
  if ($id) {
    Write-Host ("  OK   {0}" -f $p.Name)
  } else {
    Write-Host ("  MISS {0} (start platform + detection-core/apps for a live lab)" -f $p.Name)
  }
}

if ($DryRun) {
  Write-Host ""
  Write-Host "DryRun: skipping Atomic Red Team path gate and execution."
  Write-Host "OK - purple-team dry-run complete; map printed; no adversary emulation."
  exit 0
}

if ($scoreRequested) {
  $scoreArgs = @($scorer, "--expected-map", $ExpectedMap, "--findings", $FindingsPath, "--window-start", $WindowStart, "--window-end", $WindowEnd, "--report", $ReportPath)
  if ($TenantId) { $scoreArgs += @("--tenant", $TenantId) }
  & python @scoreArgs
  exit $LASTEXITCODE
}

if (-not $AtomicPath -or -not (Test-Path $AtomicPath)) {
  Write-Host @"
Atomic Red Team path not found (ATOMIC_RED_TEAM_PATH / -AtomicPath).
Install Atomic Red Team (or Caldera) outside this repo, point ATOMIC_RED_TEAM_PATH
at the checkout, and re-run - or use -DryRun to validate the expected map only.
Fail-closed: refusing to claim a purple-team run without external tooling.
"@
  exit 1
}

Write-Host ""
Write-Host "Atomic path present: $AtomicPath"
Write-Host "Harness does not auto-execute Atomic tests. Run selected techniques against a"
Write-Host "lab endpoint only, export time-bounded findings, then re-run with -FindingsPath"
Write-Host "-WindowStart -WindowEnd -ReportPath to produce a pass/fail coverage report."
Write-Host "External Atomic path present; execution remains operator-owned."
