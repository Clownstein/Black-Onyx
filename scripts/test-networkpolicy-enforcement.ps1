param(
    [Parameter(Mandatory = $true)][string]$DestinationNamespace,
    [Parameter(Mandatory = $true)][string]$ProbeImage,
    [string]$DestinationApp = "incident-api",
    [string]$AllowedSourceNamespace = "",
    [string]$AllowedSourceApp = "black-onyx",
    [int]$DestinationPort = 8083
)

$ErrorActionPreference = "Stop"
if ($ProbeImage -notmatch '^\S+@sha256:[a-f0-9]{64}$') {
    throw "ProbeImage must be a repository@sha256:digest reference."
}
if ($DestinationPort -lt 1024 -or $DestinationPort -gt 65535) {
    throw "DestinationPort must be between 1024 and 65535 for the non-root probe image."
}
if (-not $AllowedSourceNamespace) { $AllowedSourceNamespace = $DestinationNamespace }
if ($DestinationNamespace -notmatch '^[a-z0-9]([-a-z0-9]*[a-z0-9])?$' -or
    $AllowedSourceNamespace -notmatch '^[a-z0-9]([-a-z0-9]*[a-z0-9])?$' -or
    $DestinationApp -notmatch '^[A-Za-z0-9]([A-Za-z0-9_.-]{0,61}[A-Za-z0-9])?$' -or
    $AllowedSourceApp -notmatch '^[A-Za-z0-9]([A-Za-z0-9_.-]{0,61}[A-Za-z0-9])?$') {
    throw "Namespace or app selector is not a valid Kubernetes label value."
}

$context = kubectl config current-context 2>$null
if ($LASTEXITCODE -ne 0 -or -not $context) { throw "kubectl has no active cluster context." }
$testId = [Guid]::NewGuid().ToString("N").Substring(0, 10)
$targetPod = "bo-np-target-$testId"
$allowedPod = "bo-np-allowed-$testId"
$deniedNamespace = "bo-np-denied-$testId"
$deniedPod = "bo-np-denied-$testId"
$targetIp = ""

function Invoke-Kubectl {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments)
    & kubectl @Arguments
    if ($LASTEXITCODE -ne 0) { throw "kubectl command failed with exit code $LASTEXITCODE." }
}

function New-ProbePod {
    param([string]$Namespace, [string]$Name, [string]$AppLabel, [string[]]$Command)
    Invoke-Kubectl run $Name -n $Namespace --restart=Never --image=$ProbeImage `
        --image-pull-policy=IfNotPresent --labels="app=$AppLabel,black-onyx.netpol-test=$testId" `
        --command -- @Command
    Invoke-Kubectl wait -n $Namespace --for=condition=Ready "pod/$Name" --timeout=90s
}

try {
    New-ProbePod -Namespace $DestinationNamespace -Name $targetPod -AppLabel $DestinationApp `
        -Command @("python3", "-m", "http.server", "$DestinationPort", "--bind", "0.0.0.0")
    $targetIp = (& kubectl get pod $targetPod -n $DestinationNamespace -o jsonpath='{.status.podIP}').Trim()
    if ($LASTEXITCODE -ne 0 -or $targetIp -notmatch '^\d{1,3}(\.\d{1,3}){3}$') {
        throw "Could not determine the healthy target pod IPv4 address."
    }

    New-ProbePod -Namespace $AllowedSourceNamespace -Name $allowedPod -AppLabel $AllowedSourceApp `
        -Command @("python3", "-c", "import time; time.sleep(3600)")
    $positiveProbe = 'import socket,sys; c=socket.create_connection((sys.argv[1],int(sys.argv[2])),timeout=5); c.sendall(b"GET / HTTP/1.0\r\n\r\n"); print(c.recv(64).decode("ascii","replace")); c.close()'
    Invoke-Kubectl exec -n $AllowedSourceNamespace $allowedPod -- python3 -c `
        $positiveProbe $targetIp "$DestinationPort"

    Invoke-Kubectl create namespace $deniedNamespace
    New-ProbePod -Namespace $deniedNamespace -Name $deniedPod -AppLabel $AllowedSourceApp `
        -Command @("python3", "-c", "import time; time.sleep(3600)")
    & kubectl exec -n $deniedNamespace $deniedPod -- python3 -c `
        "import socket,sys; socket.create_connection((sys.argv[1],int(sys.argv[2])),timeout=3).close()" `
        $targetIp "$DestinationPort"
    if ($LASTEXITCODE -eq 0) {
        throw "A source outside the allowed namespace reached the NetworkPolicy-selected target."
    }
    Write-Host "NetworkPolicy ingress behavior passed: allowed source connected; unapproved namespace was denied."
    Write-Host "Repeat with each real source selector and service port in networkpolicy-allow-edge.yaml."
}
finally {
    & kubectl delete pod $allowedPod -n $AllowedSourceNamespace --ignore-not-found --wait=false *> $null
    & kubectl delete pod $targetPod -n $DestinationNamespace --ignore-not-found --wait=false *> $null
    if ($deniedNamespace) {
        & kubectl delete namespace $deniedNamespace --ignore-not-found --wait=false *> $null
    }
}
