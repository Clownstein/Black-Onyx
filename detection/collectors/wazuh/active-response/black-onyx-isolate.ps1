# Wazuh active response (Windows): isolate this host for Black Onyx playbooks.
#
# Dispatched with command "!black-onyx-isolate.cmd" and extra_args:
#   ttl_minutes=<n>  reason=<text>  allow=<ip|cidr> (repeatable)
# The Wazuh manager from ossec.conf is always allowed so the agent stays managed.
# Any failure while applying restores the previous firewall state. Hosts whose
# firewall is controlled by Group Policy are refused, because local rules cannot
# override policy and isolation would be incomplete.
# Manual restore: black-onyx-isolate.cmd -Restore
param([switch]$Restore)

$ErrorActionPreference = "Stop"
$AgentDir = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$LogFile = Join-Path $AgentDir "active-response\active-responses.log"
$StateFile = Join-Path $AgentDir "active-response\black-onyx-isolate.state.json"
$OssecConf = Join-Path $AgentDir "ossec.conf"
$RuleGroup = "BlackOnyxIsolation"
$TaskName = "BlackOnyxUnisolate"

function Write-Log([string]$Message) {
  $line = "{0} black-onyx-isolate: {1}" -f (Get-Date -Format "yyyy/MM/dd HH:mm:ss"), $Message
  try { Add-Content -Path $LogFile -Value $line } catch { }
}

function Test-IpOrCidr([string]$Value) {
  $parts = $Value.Split("/")
  if ($parts.Count -gt 2) { return $false }
  $address = $null
  if (-not [System.Net.IPAddress]::TryParse($parts[0], [ref]$address)) { return $false }
  if ($parts.Count -eq 2) {
    $prefix = 0
    $max = if ($address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) { 128 } else { 32 }
    if (-not [int]::TryParse($parts[1], [ref]$prefix) -or $prefix -lt 0 -or $prefix -gt $max) { return $false }
  }
  return $true
}

function Unregister-RestoreTask {
  Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
}

function Restore-Network {
  Get-NetFirewallRule -Group $RuleGroup -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
  if (Test-Path $StateFile) {
    $saved = Get-Content $StateFile -Raw | ConvertFrom-Json
    foreach ($p in @($saved.profiles)) {
      Set-NetFirewallProfile -Name $p.Name `
        -Enabled ([string]$p.Enabled) `
        -DefaultInboundAction ([string]$p.DefaultInboundAction) `
        -DefaultOutboundAction ([string]$p.DefaultOutboundAction)
    }
    $names = @($saved.disabled_rules) | Where-Object { $_ }
    if ($names.Count -gt 0) { Enable-NetFirewallRule -Name $names -ErrorAction SilentlyContinue }
    Remove-Item $StateFile -Force
  }
}

if ($Restore) {
  Restore-Network
  Unregister-RestoreTask
  Write-Log "isolation removed"
  exit 0
}

$raw = [Console]::In.ReadLine()
if (-not $raw) { Write-Log "no active-response input"; exit 0 }
$message = $raw | ConvertFrom-Json
$command = [string]$message.command
if ($command -eq "delete") {
  Restore-Network
  Unregister-RestoreTask
  Write-Log "isolation removed by delete command"
  exit 0
}
if ($command -ne "add") { Write-Log "ignoring command '$command'"; exit 0 }

$ttl = 120
$reason = ""
$allow = New-Object System.Collections.Generic.List[string]
foreach ($arg in @($message.parameters.extra_args)) {
  $text = [string]$arg
  if ($text.StartsWith("ttl_minutes=")) {
    $parsed = 0
    if ([int]::TryParse($text.Substring(12), [ref]$parsed) -and $parsed -ge 1 -and $parsed -le 10080) { $ttl = $parsed }
  } elseif ($text.StartsWith("reason=")) {
    $reason = $text.Substring(7)
  } elseif ($text.StartsWith("allow=")) {
    $entry = $text.Substring(6)
    if (Test-IpOrCidr $entry) { $allow.Add($entry) } else { Write-Log "ignoring allow entry that is not an IP address or CIDR" }
  }
}

# Resolve the manager before changing anything; isolating without it would
# cut the agent off from Wazuh and leave no way to lift isolation remotely.
if (-not (Test-Path $OssecConf)) { Write-Log "missing $OssecConf; isolation not applied"; exit 1 }
$managers = @([regex]::Matches((Get-Content $OssecConf -Raw), "<address>\s*([^<\s]+)\s*</address>") | ForEach-Object { $_.Groups[1].Value })
if ($managers.Count -eq 0) { Write-Log "no manager <address> in ossec.conf; isolation not applied"; exit 1 }
foreach ($manager in $managers) {
  if (Test-IpOrCidr $manager) { $allow.Add($manager); continue }
  try {
    $addresses = @([System.Net.Dns]::GetHostAddresses($manager) | ForEach-Object { $_.IPAddressToString })
  } catch {
    $addresses = @()
  }
  if ($addresses.Count -eq 0) { Write-Log "cannot resolve manager address $manager; isolation not applied"; exit 1 }
  foreach ($address in $addresses) { $allow.Add($address) }
}

Unregister-RestoreTask
Restore-Network
try {
  # Allow rules beat a default-block policy, so existing allow rules are disabled for
  # the isolation window and re-enabled on restore.
  $allowRules = @(Get-NetFirewallRule -Enabled True -Action Allow | Where-Object { $_.Group -ne $RuleGroup })
  $state = @{
    profiles = @(Get-NetFirewallProfile | ForEach-Object {
      @{
        Name = $_.Name
        Enabled = [string]$_.Enabled
        DefaultInboundAction = [string]$_.DefaultInboundAction
        DefaultOutboundAction = [string]$_.DefaultOutboundAction
      }
    })
    disabled_rules = @($allowRules | ForEach-Object { $_.Name })
  }
  $state | ConvertTo-Json -Depth 4 | Set-Content -Path $StateFile
  if ($allowRules.Count -gt 0) { $allowRules | Disable-NetFirewallRule }
  New-NetFirewallRule -DisplayName "Black Onyx isolation allow (out)" -Group $RuleGroup -Direction Outbound `
    -Action Allow -RemoteAddress $allow.ToArray() | Out-Null
  New-NetFirewallRule -DisplayName "Black Onyx isolation allow (in)" -Group $RuleGroup -Direction Inbound `
    -Action Allow -RemoteAddress $allow.ToArray() | Out-Null
  Set-NetFirewallProfile -All -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Block

  # The effective (ActiveStore) policy includes Group Policy; verify isolation really took.
  $effective = @(Get-NetFirewallProfile -PolicyStore ActiveStore)
  $weak = @($effective | Where-Object {
    [string]$_.Enabled -ne "True" -or [string]$_.DefaultInboundAction -ne "Block" -or [string]$_.DefaultOutboundAction -ne "Block"
  })
  $policyAllows = @(Get-NetFirewallRule -PolicyStore ActiveStore -Enabled True -Action Allow -ErrorAction SilentlyContinue |
    Where-Object { $_.Group -ne $RuleGroup })
  if ($weak.Count -gt 0 -or $policyAllows.Count -gt 0) {
    throw ("firewall policy overrides local isolation ({0} profile(s) not blocking, {1} policy allow rule(s))" -f $weak.Count, $policyAllows.Count)
  }

  $action = New-ScheduledTaskAction -Execute "$PSScriptRoot\black-onyx-isolate.cmd" -Argument "-Restore"
  $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes($ttl)
  $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
  Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null
} catch {
  Write-Log ("isolation failed, restoring network access: {0}" -f $_.Exception.Message)
  Restore-Network
  Unregister-RestoreTask
  exit 1
}
Write-Log ("isolated for {0}m (allow: {1}) reason: {2}" -f $ttl, ($allow -join " "), $reason)
exit 0
