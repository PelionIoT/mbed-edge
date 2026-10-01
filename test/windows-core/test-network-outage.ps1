# C5 helper: run from an elevated Windows PowerShell session.
# Targets is a JSON array of { processId, executable } for owned test clients.
[CmdletBinding(DefaultParameterSetName = 'Outage')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Outage')]
    [string]$Targets,
    [Parameter(Mandatory, ParameterSetName = 'Outage')]
    [string]$ResultsDirectory,
    [Parameter(ParameterSetName = 'Outage')]
    [ValidateRange(10, 90)]
    [int]$DurationSeconds = 90,
    [Parameter(Mandatory, ParameterSetName = 'Cleanup')]
    [string]$CleanupManifest,
    [Parameter(ParameterSetName = 'Cleanup')]
    [switch]$Watchdog
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Remove-TestRules($Manifest) {
    foreach ($entry in $Manifest.rules) {
        if ($entry.name -notmatch '^EdgeCore-C5-[0-9a-f]{32}-[0-9]+$') {
            throw 'Refusing to remove a rule outside this test namespace.'
        }
        $rule = Get-NetFirewallRule -PolicyStore PersistentStore -Name $entry.name -ErrorAction SilentlyContinue
        if ($rule) {
            $filter = $rule | Get-NetFirewallApplicationFilter
            if ($filter.Program -ne $entry.executable -or $rule.Direction -ne 'Outbound' -or $rule.Action -ne 'Block') {
                throw "Refusing to remove changed rule $($entry.name)."
            }
            $rule | Remove-NetFirewallRule
        }
        if (Get-NetFirewallRule -PolicyStore PersistentStore -Name $entry.name -ErrorAction SilentlyContinue) {
            throw "Rule $($entry.name) is still present."
        }
    }
}

if ($PSCmdlet.ParameterSetName -eq 'Cleanup') {
    $manifest = Get-Content -LiteralPath $CleanupManifest -Raw | ConvertFrom-Json
    if ($Watchdog) {
        $deadline = [DateTimeOffset]::Parse($manifest.cleanupDeadlineUtc)
        # Reject accidental unbounded watchdogs before waiting.
        if (($deadline - [DateTimeOffset]::UtcNow).TotalSeconds -gt 150) {
            throw 'Cleanup deadline is too far in the future.'
        }
        while ([DateTimeOffset]::UtcNow -lt $deadline) { Start-Sleep -Seconds 1 }
    }
    try {
        Remove-TestRules $manifest
        @{ cleanedUtc = [DateTimeOffset]::UtcNow.ToString('o'); error = $null } |
            ConvertTo-Json | Set-Content -LiteralPath ($CleanupManifest + '.cleanup.json') -Encoding UTF8
    } catch {
        @{ cleanedUtc = $null; error = $_.Exception.Message } |
            ConvertTo-Json | Set-Content -LiteralPath ($CleanupManifest + '.cleanup.json') -Encoding UTF8
        throw
    }
    return
}

$outputDirectory = (Resolve-Path -LiteralPath $ResultsDirectory).Path
$statusPath = Join-Path $outputDirectory 'outage-status.json'
$manifestPath = Join-Path $outputDirectory 'firewall-rules.json'
if ((Test-Path -LiteralPath $statusPath) -or (Test-Path -LiteralPath $manifestPath)) {
    throw 'Use a new results directory for each outage.'
}
$status = [ordered]@{
    stage = 'preflight'; createdUtc = [DateTimeOffset]::UtcNow.ToString('o')
    blockedUtc = $null; restoredUtc = $null; cleanupVerified = $false
    durationSeconds = $DurationSeconds; rules = @(); error = $null
}
function Save-Status { $status | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $statusPath -Encoding UTF8 }
$manifest = $null
try {
    Save-Status
    $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Windows Firewall administration requires an elevated PowerShell session.'
    }
    # Requiring all profiles avoids a false outage pass on a disabled active profile.
    $profiles = @(Get-NetFirewallProfile)
    if ($profiles.Count -ne 3 -or @($profiles | Where-Object { -not $_.Enabled }).Count) {
        throw 'Enable the applicable firewall profiles before testing; this helper does not change them.'
    }
    # Windows PowerShell 5.1 emits a JSON array as one pipeline object.
    $decodedClients = Get-Content -LiteralPath $Targets -Raw | ConvertFrom-Json
    $clients = @($decodedClients)
    if ($clients.Count -lt 1 -or $clients.Count -gt 2) { throw 'Supply one or two test clients.' }
    $tag = [Guid]::NewGuid().ToString('N')
    $index = 0
    foreach ($client in $clients) {
        $executable = (Resolve-Path -LiteralPath $client.executable).Path
        if ([IO.Path]::GetFileName($executable) -ne 'edge-core.exe') { throw 'Only edge-core.exe is supported.' }
        $process = Get-Process -Id $client.processId
        if ($process.Path -ne $executable) { throw 'Process ID no longer belongs to the specified executable.' }
        if (@($status.rules | Where-Object { $_.executable -eq $executable }).Count) { throw 'Duplicate executable.' }
        $status.rules += @{ name = "EdgeCore-C5-$tag-$index"; executable = $executable; processId = $client.processId }
        $index++
    }
    $manifest = @{
        rules = $status.rules
        cleanupDeadlineUtc = [DateTimeOffset]::UtcNow.AddSeconds($DurationSeconds + 30).ToString('o')
    }
    $manifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $manifestPath -Encoding UTF8
    # The independent process survives termination of the main test helper.
    $shell = Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/powershell.exe'
    $arguments = '-NoProfile -ExecutionPolicy Bypass -File "{0}" -CleanupManifest "{1}" -Watchdog' -f $PSCommandPath, $manifestPath
    $cleanupProcess = Start-Process -FilePath $shell -ArgumentList $arguments -WindowStyle Hidden -PassThru
    if ($cleanupProcess.HasExited) { throw 'Cleanup watchdog did not start.' }
    foreach ($entry in $manifest.rules) {
        New-NetFirewallRule -PolicyStore PersistentStore -Name $entry.name -DisplayName $entry.name `
            -Direction Outbound -Action Block -Program $entry.executable -Profile Any -Enabled True | Out-Null
        $rule = Get-NetFirewallRule -PolicyStore ActiveStore -Name $entry.name
        $filter = $rule | Get-NetFirewallApplicationFilter
        if ($rule.Enabled -ne 'True' -or $rule.Direction -ne 'Outbound' -or $rule.Action -ne 'Block' -or $filter.Program -ne $entry.executable) {
            throw 'The requested program block is not active.'
        }
    }
    $status.stage = 'blocked'
    $status.blockedUtc = [DateTimeOffset]::UtcNow.ToString('o')
    Save-Status
    $stopwatch = [Diagnostics.Stopwatch]::StartNew()
    while ($stopwatch.Elapsed.TotalSeconds -lt $DurationSeconds) { Start-Sleep -Milliseconds 250 }
} catch {
    $status.error = $_.Exception.Message
} finally {
    if ($null -ne $manifest) {
        try {
            Remove-TestRules $manifest
            $status.restoredUtc = [DateTimeOffset]::UtcNow.ToString('o')
            $status.cleanupVerified = $true
        } catch {
            $status.error = "$($status.error) Cleanup failed: $($_.Exception.Message)"
        }
    }
    $status.stage = if ($status.error) { 'failed' } else { 'restored' }
    Save-Status
}
if ($status.error) { throw $status.error }
