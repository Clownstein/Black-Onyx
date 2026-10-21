# Install the Black Onyx isolation active-response script on a Windows Wazuh agent. Run elevated.
$ErrorActionPreference = "Stop"
$agentDir = if (Test-Path "${env:ProgramFiles(x86)}\ossec-agent") { "${env:ProgramFiles(x86)}\ossec-agent" } else { "$env:ProgramFiles\ossec-agent" }
$binDir = Join-Path $agentDir "active-response\bin"
if (-not (Test-Path $binDir)) { throw "$binDir not found; install the Wazuh agent first" }
$source = Join-Path $PSScriptRoot "active-response"
Copy-Item (Join-Path $source "black-onyx-isolate.cmd") $binDir -Force
Copy-Item (Join-Path $source "black-onyx-isolate.ps1") $binDir -Force
Write-Host "Installed black-onyx-isolate.cmd and black-onyx-isolate.ps1 to $binDir"
