# Starts Python Phase 0 services against local compose infra.
$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..\..")
Set-Location $Root

$env:ASSET_REGISTRY_DATABASE_URL = "postgresql+psycopg://anomaly:anomaly@localhost:5432/asset_registry"
$env:SMOKE_DATABASE_URL = "postgresql+psycopg://anomaly:anomaly@localhost:5432/smoke"
$env:SMOKE_KAFKA_BROKERS = "localhost:19092"
$env:KAFKA_BROKERS = "localhost:19092"
$env:API_KEYS = "dev-ingest-key"

Write-Host "Starting asset-registry :8081, smoke-consumer :8082, incident-api :8083"
Write-Host "Start ingestion-gateway separately with Go: cd services/ingestion-gateway; go run ./cmd/server"

Start-Process -NoNewWindow python -ArgumentList "-m", "uvicorn", "asset_registry.main:app", "--app-dir", "services/asset-registry", "--host", "0.0.0.0", "--port", "8081"
Start-Process -NoNewWindow python -ArgumentList "-m", "uvicorn", "smoke_consumer.main:app", "--app-dir", "services/smoke-consumer", "--host", "0.0.0.0", "--port", "8082"
Start-Process -NoNewWindow python -ArgumentList "-m", "uvicorn", "incident_api.main:app", "--app-dir", "services/incident-api", "--host", "0.0.0.0", "--port", "8083"

Write-Host "Services launched. Press Ctrl+C in each job window / stop processes when done."
