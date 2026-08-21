$ErrorActionPreference = "Continue"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$Py = Join-Path $Root ".venv\Scripts\python.exe"
$UseUv = $true
if (Test-Path $Py) {
  & $Py --version *> $null
  $UseUv = $LASTEXITCODE -ne 0
}
$SystemPy = (Get-Command python -ErrorAction Stop).Source
if ($UseUv) {
  $Uv = (Get-Command uv -ErrorAction Stop).Source
  $cachePath = Join-Path $Root ".codex-cache\uv"
  $tempPath = Join-Path $Root ".codex-test-tmp\runner"
  New-Item -ItemType Directory -Force -Path $cachePath, $tempPath | Out-Null
  $env:UV_CACHE_DIR = $cachePath
  $env:TEMP = $tempPath
  $env:TMP = $tempPath
}

$failed = 0

function Run-Pytest([string]$Title, [string]$WorkDir, [string[]]$Targets) {
  Write-Host "`n=== $Title ===" -ForegroundColor Cyan
  Push-Location $WorkDir
  try {
    if ($UseUv) {
      $uvArgs = @(
        "run", "--isolated", "--no-managed-python", "--python", $SystemPy
      )
      $projectFile = Join-Path $WorkDir "pyproject.toml"
      if (
        (Test-Path $projectFile) -and
        (Select-String -LiteralPath $projectFile -Pattern '^\s*dev\s*=' -Quiet)
      ) {
        $uvArgs += @("--extra", "dev")
      }
      if ($WorkDir -eq $Root) {
        $uvArgs += @("--extra", "dev")
        if ($Title -eq "contract+security") {
          $uvArgs += @("--with-editable", (Join-Path $Root "packages\black_onyx_contracts"))
        } elseif ($Title -eq "golden-scenario") {
          $uvArgs += @("--with-editable", (Join-Path $Root "services\correlation-engine"))
        } elseif ($Title -eq "features-to-incident") {
          $uvArgs += @(
            "--with-editable", (Join-Path $Root "services\correlation-engine"),
            "--with-editable", (Join-Path $Root "services\incident-api")
          )
        } elseif ($Title -eq "tenant-isolation") {
          $uvArgs += @("--with-editable", (Join-Path $Root "services\incident-api"))
        }
      }
      $uvArgs += @("python", "-m", "pytest")
      $uvArgs += $Targets
      $uvArgs += @("-o", "testpaths=.", "-q", "--tb=line", "-p", "no:cacheprovider")
      & $Uv @uvArgs
    } else {
      & $Py -m pytest @Targets -o "testpaths=." -q --tb=line
    }
    if ($LASTEXITCODE -ne 0) { $script:failed++ }
  } finally {
    Pop-Location
  }
}

Run-Pytest "contract+security" $Root @(
  "tests/contract",
  "tests/security/test_xss_escape.py",
  "tests/security/test_webhook_signature.py"
)

$env:PYTHONPATH = Join-Path $Root "packages\black_onyx_calibration\src"
Run-Pytest "black-onyx-calibration" (Join-Path $Root "packages\black_onyx_calibration") @("tests")
Remove-Item Env:PYTHONPATH -ErrorAction SilentlyContinue

$packages = @(
  "services\asset-registry",
  "services\incident-api",
  "services\correlation-engine",
  "services\threat-intel-service",
  "services\log-processor",
  "services\flow-processor",
  "services\metrics-processor",
  "services\code-processor",
  "services\host-state-processor",
  "services\firewall-processor",
  "services\ids-processor",
  "services\integration-hub",
  "services\code-enrichment-worker",
  "services\embedding-worker",
  "services\profile-evaluator",
  "services\response-orchestrator",
  "packages\black_onyx_vector",
  "services\malware-triage",
  "services\malware-orchestrator",
  "services\malware-processor",
  "services\profile-evaluator",
  "services\model-gateway",
  "services\notification-service",
  "services\training-orchestrator",
  "services\inference-worker",
  "models\log-model",
  "models\code-model",
  "models\network-model",
  "models\metrics-model",
  "models\host-state-model",
  "models\malware-static"
)

foreach ($rel in $packages) {
  $dir = Join-Path $Root $rel
  if (-not (Test-Path (Join-Path $dir "tests"))) { continue }
  if ($rel -eq "packages\black_onyx_vector") {
    $env:PYTHONPATH = Join-Path $dir "src"
  } else {
    $env:PYTHONPATH = "$dir"
  }
  Run-Pytest $rel $dir @("tests")
  Remove-Item Env:PYTHONPATH -ErrorAction SilentlyContinue
}

$statefulServices = @(
  "services\asset-registry",
  "services\incident-api",
  "services\response-orchestrator",
  "services\integration-hub",
  "services\training-orchestrator",
  "services\threat-intel-service",
  "services\notification-service",
  "services\smoke-consumer"
)
foreach ($rel in $statefulServices) {
  $dir = Join-Path $Root $rel
  Write-Host "`n=== migration parity: $rel ===" -ForegroundColor Cyan
  Push-Location $dir
  try {
    $env:PYTHONPATH = $dir
    if ($UseUv) {
      $uvArgs = @(
        "run", "--isolated", "--no-managed-python", "--python", $SystemPy
      )
      $projectFile = Join-Path $dir "pyproject.toml"
      if (Select-String -LiteralPath $projectFile -Pattern '^\s*dev\s*=' -Quiet) {
        $uvArgs += @("--extra", "dev")
      }
      $uvArgs += @(
        "python",
        (Join-Path $Root "scripts\development\check_migration_parity.py"),
        "--service",
        $dir
      )
      & $Uv @uvArgs
    } else {
      & $Py (Join-Path $Root "scripts\development\check_migration_parity.py") --service $dir
    }
    if ($LASTEXITCODE -ne 0) { $failed++ }
  } finally {
    Remove-Item Env:PYTHONPATH -ErrorAction SilentlyContinue
    Pop-Location
  }
}

$env:PYTHONPATH = Join-Path $Root "services\correlation-engine"
Run-Pytest "golden-scenario" $Root @("tests/integration/test_golden_scenario.py")
Remove-Item Env:PYTHONPATH -ErrorAction SilentlyContinue

Run-Pytest "features-to-incident" $Root @("tests/integration/test_features_to_incident.py")

Run-Pytest "retention" $Root @("tests/integration/test_retention_job.py")

$env:PYTHONPATH = Join-Path $Root "services\incident-api"
Run-Pytest "tenant-isolation" $Root @("tests/security/test_tenant_isolation.py", "tests/security/test_rbac.py")
Remove-Item Env:PYTHONPATH -ErrorAction SilentlyContinue

if ($failed -gt 0) {
  Write-Host "`n$failed suite(s) failed" -ForegroundColor Red
  exit 1
}
Write-Host "`nAll suites passed" -ForegroundColor Green
