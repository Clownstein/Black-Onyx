# Soft-smoke for optional Prometheus/Grafana observability overlay.
# From repo root:
#
#   docker compose -f docker-compose.yml -f docker-compose.platform.yml `
#     -f docker-compose.detection-apps.yml `
#     -f detection/infrastructure/docker-compose/docker-compose.observability.yml up -d
#   powershell -File scripts/smoke_observability.ps1
#
# Soft-skips (exit 0) when Prometheus is not running unless -RequireStack is set.
# When Prometheus is up, also asserts at least one configured scrape target via
# /api/v1/targets (active or dropped targets).
#
#   powershell -File scripts/smoke_observability.ps1 -RequireStack

param(
  [switch]$RequireStack
)

$ErrorActionPreference = "Stop"

Write-Host "Observability smoke: joining optional overlay onto root compose"
Write-Host "  docker compose -f docker-compose.yml -f docker-compose.platform.yml ``"
Write-Host "    -f docker-compose.detection-apps.yml ``"
Write-Host "    -f detection/infrastructure/docker-compose/docker-compose.observability.yml up -d"
Write-Host ""

$prom = $null
try {
  $prom = docker ps -q -f name=blackonyx-prometheus 2>$null
} catch {
  $prom = $null
}
if (-not $prom) {
  if ($RequireStack) {
    Write-Error "Prometheus container blackonyx-prometheus is not running."
    Write-Host "Start the observability overlay - see docs/DEVELOPMENT.md and docs/DEPLOYMENT.md - then re-run with -RequireStack."
    exit 1
  }
  Write-Host "SKIP: Prometheus container blackonyx-prometheus is not running."
  Write-Host "Start the observability overlay - see docs/DEVELOPMENT.md and docs/DEPLOYMENT.md - then re-run."
  exit 0
}

Write-Host "Checking Prometheus ready via compose network..."
docker exec blackonyx-prometheus sh -c "command -v wget >/dev/null && wget -qO- http://127.0.0.1:9090/-/ready || command -v curl >/dev/null && curl -fsS http://127.0.0.1:9090/-/ready"
if ($LASTEXITCODE -ne 0) {
  throw "Prometheus container is up but /-/ready was not reachable from inside the container."
}

Write-Host "Checking Prometheus scrape targets via /api/v1/targets..."
$targetsJson = docker exec blackonyx-prometheus sh -c "command -v wget >/dev/null && wget -qO- http://127.0.0.1:9090/api/v1/targets || command -v curl >/dev/null && curl -fsS http://127.0.0.1:9090/api/v1/targets"
if ($LASTEXITCODE -ne 0) {
  throw "Prometheus /api/v1/targets was not reachable from inside the container."
}
$targets = $targetsJson | ConvertFrom-Json
if ($targets.status -ne "success") {
  throw "Prometheus /api/v1/targets returned status '$($targets.status)'."
}
$activeCount = @($targets.data.activeTargets).Count
$droppedCount = @($targets.data.droppedTargets).Count
if ($activeCount -le 0 -and $droppedCount -le 0) {
  throw "Prometheus has no configured scrape targets (active=$activeCount, dropped=$droppedCount)."
}
Write-Host "Prometheus scrape targets: active=$activeCount dropped=$droppedCount"
Write-Host "OK - observability smoke (reachability + scrape target presence; not a full SLO proof)."
