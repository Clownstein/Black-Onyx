# Assert the CPU log-model training path resolves for training-orchestrator.
# From repo root:
#
#   powershell -File scripts/smoke_training_path.ps1
#
# Does not run training or require GPU - only path existence + import resolution.

$ErrorActionPreference = "Stop"

$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$trainPy = Join-Path $repoRoot "detection\models\log-model\training\train.py"
if (-not (Test-Path $trainPy)) {
  throw "Missing trainer script: $trainPy"
}
Write-Host "Found: $trainPy"

$uv = Get-Command uv -ErrorAction SilentlyContinue
if ($uv) {
  Write-Host "Resolving trainer_script_path('log-model') via training_orchestrator..."
  $orchDir = Join-Path $repoRoot "services\training-orchestrator"
  Push-Location $orchDir
  try {
    $env:PYTHONPATH = $orchDir
    uv run python -c "from pathlib import Path; from training_orchestrator.training import trainer_script_path; p = trainer_script_path('log-model'); assert p is not None and Path(p).is_file(), p; print(p)"
    if ($LASTEXITCODE -ne 0) {
      throw "trainer_script_path('log-model') did not resolve to an existing file"
    }
  } finally {
    Pop-Location
  }
} else {
  Write-Host "uv not on PATH - falling back to path existence check only."
  Write-Host "Expected orchestrator resolve: detection/models/log-model/training/train.py"
}

Write-Host "OK - training path smoke for CPU log-model path only; no training run."
