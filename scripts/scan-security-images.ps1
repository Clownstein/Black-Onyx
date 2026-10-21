param(
    [Parameter(Mandatory = $true)][string]$ToolboxImage,
    [Parameter(Mandatory = $true)][string]$GuardImage,
    [Parameter(Mandatory = $true)][string]$RunnerImage,
    [Parameter(Mandatory = $true)][string]$GatewayImage
)

$ErrorActionPreference = "Stop"
$images = @($ToolboxImage, $GuardImage, $RunnerImage, $GatewayImage)
foreach ($image in $images) {
    if ($image -notmatch '^\S+@sha256:[a-f0-9]{64}$') {
        throw "Every final image must be supplied as repository@sha256:digest: $image"
    }
    docker image inspect $image *> $null
    if ($LASTEXITCODE -ne 0) {
        throw "Image is not present locally; this gate does not pull images: $image"
    }
}

if (-not (Get-Command trivy -ErrorAction SilentlyContinue)) {
    throw "Trivy is required for the final-image scan gate. Install the approved scanner, then rerun this script."
}

foreach ($image in $images) {
    Write-Host "Scanning $image"
    trivy image --scanners vuln,secret,misconfig --severity HIGH,CRITICAL --exit-code 1 $image
    if ($LASTEXITCODE -ne 0) {
        throw "Final-image scan failed: $image"
    }
}

docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges:true `
    --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m --user 10001:10001 `
    --entrypoint python3 $ToolboxImage /usr/share/blackonyx/toolbox_smoke.py
if ($LASTEXITCODE -ne 0) {
    throw "Toolbox import, binary, or bounded-wordlist smoke failed"
}

docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges:true `
    --user 10001:10001 --entrypoint python $RunnerImage -c "from security_runner.app import app; print(app.title)"
if ($LASTEXITCODE -ne 0) {
    throw "Security runner final-image import smoke failed"
}

docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges:true `
    --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m --user 10001:10001 `
    --entrypoint python $GatewayImage -c "from security_gateway.app import app; print(app.title)"
if ($LASTEXITCODE -ne 0) {
    throw "Security gateway final-image import smoke failed"
}

docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges:true `
    --entrypoint /bin/sh $GuardImage -ec "command -v nft && command -v tcpdump && command -v timeout"
if ($LASTEXITCODE -ne 0) {
    throw "Firewall guard final-image utility smoke failed"
}

Write-Host "All four image scans and offline startup/import smokes passed."
