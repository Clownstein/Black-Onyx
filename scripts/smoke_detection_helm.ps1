# Render-check the detection Helm chart. Optionally dry-run apply when a cluster
# is available. From repo root:
#
#   powershell -File scripts/smoke_detection_helm.ps1
#
# Always prefers helm when available. If helm is missing, exits 0 with a skip
# message (template check cannot run). Cluster apply is optional; exits 0 with a
# skip message when kind/kubectl has no usable cluster. Does not prove a live
# cluster deploy.

$ErrorActionPreference = "Stop"

$chart = [System.IO.Path]::GetFullPath(
  (Join-Path $PSScriptRoot "..\deploy\detection\helm\black-onyx-detection")
)
if (-not (Test-Path (Join-Path $chart "Chart.yaml"))) {
  throw "Chart not found at $chart"
}

$helmCmd = Get-Command helm -ErrorAction SilentlyContinue
if (-not $helmCmd) {
  Write-Host "SKIP: helm is not on PATH. Install Helm 3.x to render-check the chart."
  exit 0
}

Write-Host "Running helm lint on $chart ..."
& helm lint $chart | Out-Null
if ($LASTEXITCODE -ne 0) {
  throw "helm lint failed"
}

# Every combination README.md documents. The chart requires an OIDC profile
# values.yaml ships issuer/audience/jwksUrl empty and the templates `required`
# them so a bare render, or values-airgap.yaml on its own, fails by design.
$profiles = @(
  @("values.yaml", "values-dev.yaml"),
  @("values.yaml", "values-prod.yaml"),
  @("values.yaml", "values-prod.yaml", "values-airgap.yaml")
)
foreach ($profile in $profiles) {
  $valueArgs = @()
  foreach ($file in $profile) { $valueArgs += "-f"; $valueArgs += (Join-Path $chart $file) }
  Write-Host ("Running helm template with {0} ..." -f ($profile -join " + "))
  & helm template black-onyx-detection $chart @valueArgs | Out-Null
  if ($LASTEXITCODE -ne 0) {
    throw ("helm template failed for {0}" -f ($profile -join " + "))
  }
}
Write-Host "helm lint + template: OK"

$kubectlCmd = Get-Command kubectl -ErrorAction SilentlyContinue
if (-not $kubectlCmd) {
  Write-Host "SKIP: kubectl not on PATH - cluster dry-run not attempted."
  exit 0
}

$serverOk = $false
& kubectl cluster-info 2>$null | Out-Null
if ($LASTEXITCODE -eq 0) { $serverOk = $true }

if (-not $serverOk) {
  Write-Host "SKIP: no reachable Kubernetes cluster (kind/kubectl). Template-only smoke complete."
  exit 0
}

Write-Host "Cluster reachable - helm upgrade --install --dry-run ..."
& helm upgrade --install black-onyx-detection-smoke $chart `
  -f (Join-Path $chart "values.yaml") `
  -f (Join-Path $chart "values-prod.yaml") `
  --dry-run `
  | Out-Null
if ($LASTEXITCODE -ne 0) {
  throw "helm dry-run failed"
}
Write-Host "OK - helm template + dry-run complete (not a live deploy proof)."
