[CmdletBinding()]
param(
    [string]$OutputPath
)

$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
if (-not $OutputPath) {
    $OutputPath = Join-Path $repoRoot "infrastructure\docker-compose\.env.local"
}
$resolvedOutput = [System.IO.Path]::GetFullPath($OutputPath)
if (-not $resolvedOutput.StartsWith($repoRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "OutputPath must stay inside the repository: $repoRoot"
}
if (Test-Path -LiteralPath $resolvedOutput) {
    throw "Refusing to overwrite existing secrets file: $resolvedOutput"
}

function New-RandomSecret {
    param([int]$Bytes = 32)
    $buffer = New-Object byte[] $Bytes
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($buffer)
    }
    finally {
        $rng.Dispose()
    }
    return [Convert]::ToBase64String($buffer).TrimEnd("=").Replace("+", "-").Replace("/", "_")
}

$lines = @(
    "# Generated local Compose secrets. Never commit this file.",
    "ALLOW_DEMO_KEYS=false",
    "POSTGRES_PASSWORD=$(New-RandomSecret)",
    "REDIS_PASSWORD=$(New-RandomSecret)",
    "OPENSEARCH_INITIAL_ADMIN_PASSWORD=Aa1!$(New-RandomSecret 24)",
    "MINIO_ROOT_USER=anomaly-minio",
    "MINIO_ROOT_PASSWORD=$(New-RandomSecret)",
    "API_KEYS=$(New-RandomSecret)",
    "INCIDENT_API_SERVICE_KEY=$(New-RandomSecret)",
    "ASSET_REGISTRY_SERVICE_KEY=$(New-RandomSecret)",
    "THREAT_INTEL_SERVICE_API_KEY=$(New-RandomSecret)",
    "INTEGRATION_HUB_API_KEY=$(New-RandomSecret)",
    "RESPONSE_ORCHESTRATOR_API_KEY=$(New-RandomSecret)",
    "RESPONSE_ORCHESTRATOR_APPROVER_API_KEY=$(New-RandomSecret)",
    "MALWARE_SERVICE_API_KEY=$(New-RandomSecret)",
    "NOTIFICATION_API_KEY=$(New-RandomSecret)",
    "NOTIFICATION_WEBHOOK_SECRET=$(New-RandomSecret)",
    "TRAINING_ARTIFACT_SIGNING_KEY=$(New-RandomSecret)",
    "GRAFANA_ADMIN_PASSWORD=$(New-RandomSecret)"
)
$parent = Split-Path -Parent $resolvedOutput
New-Item -ItemType Directory -Force -Path $parent | Out-Null
[System.IO.File]::WriteAllLines(
    $resolvedOutput,
    $lines,
    [System.Text.UTF8Encoding]::new($false)
)
Write-Output "Generated local secrets: $resolvedOutput"
