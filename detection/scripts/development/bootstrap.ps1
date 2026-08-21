# Phase 0 local bootstrap (Windows PowerShell).
# From repo root: .\detection\scripts\development\bootstrap.ps1
# Prefer: docker compose -f docker-compose.yml -f docker-compose.platform.yml up -d

$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..\..\..")
Set-Location $Root

$ComposeArgs = @("-f", "docker-compose.yml", "-f", "docker-compose.platform.yml")
$Brokers = if ($env:KAFKA_BOOTSTRAP_SERVERS) { $env:KAFKA_BOOTSTRAP_SERVERS } else { "localhost:19092" }

Write-Host "==> Ensuring Kafka topics on $Brokers"
$topics = @("logs.raw", "logs.raw.dlq")
foreach ($topic in $topics) {
    docker compose @ComposeArgs exec -T redpanda rpk topic create $topic --brokers redpanda:9092 2>$null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "    topic create skipped or already exists: $topic"
    }
}

Write-Host "==> uv sync (workspace)"
if (Get-Command uv -ErrorAction SilentlyContinue) {
    uv sync --all-packages --extra dev
} else {
    Write-Warning "uv not found; falling back to pip editable installs"
    python -m pip install -U pip
    python -m pip install -e "packages/black_onyx_contracts"
    python -m pip install -e "services/asset-registry[dev]"
    python -m pip install -e "services/smoke-consumer"
    python -m pip install -e "services/incident-api[dev]"
    python -m pip install -e ".[dev]"
}

Write-Host "==> Alembic upgrade asset-registry"
Push-Location (Join-Path $Root "services\asset-registry")
try {
    if (Get-Command uv -ErrorAction SilentlyContinue) {
        uv run alembic upgrade head
    } else {
        alembic upgrade head
    }
} finally {
    Pop-Location
}

Write-Host "==> Alembic upgrade incident-api"
Push-Location (Join-Path $Root "services\incident-api")
try {
    if (Get-Command uv -ErrorAction SilentlyContinue) {
        uv run alembic upgrade head
    } else {
        alembic upgrade head
    }
} finally {
    Pop-Location
}

Write-Host "==> Bootstrap complete"
