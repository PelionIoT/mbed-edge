# SPDX-License-Identifier: Apache-2.0
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$OutputDirectory,
    [ValidateSet('Status', 'Set', 'Observe', 'Stop')][string]$Action = 'Status',
    [long]$Value,
    [string]$GatewayId,
    [string]$ResourcePath,
    [string]$ReadStartedUtc,
    [string]$Screenshot
)
$ErrorActionPreference = 'Stop'
$resultFile = Join-Path $OutputDirectory 'result.json'
$result = Get-Content -LiteralPath $resultFile -Raw | ConvertFrom-Json
if ($Action -eq 'Status') { $result; return }
if ($result.stage -in @('passed', 'failed', 'stopping')) { throw 'This PT test is no longer accepting commands.' }
if (-not (Get-Process -Id $result.processId -ErrorAction SilentlyContinue)) { throw 'The test PT is no longer running.' }
$command = [ordered]@{ action=$Action.ToLowerInvariant() }
if ($Action -in @('Set', 'Observe')) {
    if (-not $PSBoundParameters.ContainsKey('Value')) { throw 'Supply -Value.' }
    $command.value = $Value
}
if ($Action -eq 'Observe') {
    if (-not $GatewayId -or -not $ResourcePath -or -not $ReadStartedUtc -or -not $Screenshot) {
        throw 'Supply the gateway ID, full gateway resource path, fresh read start UTC timestamp and screenshot filename.'
    }
    $command.gatewayId = $GatewayId
    $command.resourcePath = $ResourcePath
    $command.readStartedUtc = $ReadStartedUtc
    $command.screenshot = $Screenshot
}
# The PT checks every command and logs rejection without changing its counter.
$encoded = ($command | ConvertTo-Json -Depth 4 -Compress) + "`n"
[IO.File]::AppendAllText((Join-Path $OutputDirectory 'commands.jsonl'), $encoded, (New-Object Text.UTF8Encoding($false)))
Write-Output "Queued $Action; inspect result.json and events.jsonl for the acknowledgement."
