# SPDX-License-Identifier: Apache-2.0
# Administrator-only updater; edge-core's restricted token never performs it.
[CmdletBinding()]
param(
    [ValidateSet('Upgrade','Recover')][string]$Action='Upgrade',
    [ValidatePattern('^[A-Za-z0-9_.-]{1,80}$')][string]$ServiceName='EdgeCore',
    [string]$PackageDirectory,
    [string]$ReleaseDirectory,
    [switch]$AllowUnsigned,
    [string]$SignerThumbprint,
    [switch]$RequireCloud
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'package-tools.ps1')
. (Join-Path $PSScriptRoot 'service-tools.ps1')
Assert-EdgeAdministrator
function Service-Info { Get-CimInstance Win32_Service -Filter "Name='$ServiceName'" }
function Set-Command { param([string]$Command); Invoke-EdgeServiceControl @('config',$ServiceName,'binPath=',$Command) | Out-Null }
function Stop-OwnedService {
    $service=Service-Info
    if ($service.State -ne 'Stopped') {
        Stop-Service $ServiceName
        (Get-Service $ServiceName).WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped,[TimeSpan]::FromSeconds(30))
    }
    if ((Service-Info).ExitCode -ne 0) { throw 'The running service did not stop cleanly.' }
}
function Write-Journal {
    param($Value)
    $temporary=$journalPath+'.pending'
    $Value | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $temporary -Encoding UTF8
    Move-Item -LiteralPath $temporary -Destination $journalPath -Force
}
function Restore-Previous {
    param($Transaction)
    $current=Service-Info
    if ($current.PathName -notin @($Transaction.oldCommand,$Transaction.newCommand)) { throw 'Service command changed; refusing rollback.' }
    if ($current.State -ne 'Stopped') {
        Stop-Service $ServiceName
        (Get-Service $ServiceName).WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped,[TimeSpan]::FromSeconds(30))
    }
    Set-Command $Transaction.oldCommand
    $Transaction.oldInstallation | ConvertTo-Json | Set-Content -LiteralPath $installationPath -Encoding UTF8
    if ($Transaction.oldRelease) {
        $Transaction.oldRelease | ConvertTo-Json | Set-Content -LiteralPath $releaseMarker -Encoding UTF8
    } elseif (Test-Path -LiteralPath $releaseMarker) {
        # This exact metadata file is owned by the Edge installer, not identity.
        Remove-Item -LiteralPath $releaseMarker
    }
    if ($Transaction.wasRunning) {
        Start-Service $ServiceName
        Wait-EdgeServiceReady $ServiceName $Transaction.oldCommand $Transaction.httpPort
    }
    $Transaction.stage='RolledBack'
    Write-Journal $Transaction
}
$service=Service-Info
if (-not $service -or $service.StartName -ne 'NT AUTHORITY\LocalService') { throw 'Expected an existing restricted LocalService installation.' }
$image=[regex]::Match($service.PathName,'^"(?<exe>[A-Za-z]:[^"]*\\edge-core\.exe)"(?<arguments>\s+--service\s+.*)$')
$state=[regex]::Match($service.PathName,'--data-dir\s+"(?<state>[A-Za-z]:[^"]*\\state)"')
$port=[regex]::Match($service.PathName,'--http-port\s+(?<port>\d+)(\s|$)')
if (-not $image.Success -or -not $state.Success -or -not $port.Success -or
    $service.PathName -notmatch ('--service-name\s+'+[regex]::Escape($ServiceName)+'(\s|$)')) {
    throw 'Service was not installed by the native Edge installer.'
}
$oldDirectory=Get-EdgeLocalDirectory ([IO.Path]::GetDirectoryName($image.Groups['exe'].Value))
$data=Get-EdgeLocalDirectory ([IO.Path]::GetDirectoryName($state.Groups['state'].Value))
$installationPath=Join-Path $data 'service-install.json'
$releaseMarker=Join-Path $data 'service-release.json'
$installation=Get-Content -LiteralPath $installationPath -Raw | ConvertFrom-Json
if ($installation.serviceName -ne $ServiceName -or $installation.schemaVersion -ne 1) { throw 'Installation ownership marker mismatch.' }
$journalPath=Join-Path $data 'service-update.json'
$lock=[IO.File]::Open((Join-Path $data 'service-update.lock'),[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
try {
    if ($Action -eq 'Recover') {
        $transaction=Get-Content -LiteralPath $journalPath -Raw | ConvertFrom-Json
        if ($transaction.schema -ne 1 -or $transaction.serviceName -ne $ServiceName -or
            $transaction.stage -notin @('Prepared','Switched','RolledBack')) { throw 'No recoverable transaction.' }
        Restore-Previous $transaction
        Write-Output 'Recovered previous service command; identity and configuration retained.'
        return
    }
    if (-not $PackageDirectory -or -not $ReleaseDirectory) { throw 'Specify -PackageDirectory and a new -ReleaseDirectory.' }
    if ($installation.installDirectory -ne $oldDirectory) { throw 'Active binary directory does not match installation ownership marker.' }
    if (Test-Path -LiteralPath $journalPath) {
        $previous=Get-Content -LiteralPath $journalPath -Raw | ConvertFrom-Json
        if ($previous.stage -notin @('Complete','RolledBack')) { throw 'Recover the unfinished transaction before upgrading.' }
    }
    $manifest=Test-EdgePackage -Directory $PackageDirectory -AllowUnsigned:$AllowUnsigned -SignerThumbprint $SignerThumbprint
    $release=Get-EdgeLocalDirectory $ReleaseDirectory
    if (Test-Path -LiteralPath $release) { throw 'ReleaseDirectory must be new; existing binaries are retained.' }
    foreach ($directory in @($data,$oldDirectory)) {
        if ($release -eq $directory -or $release.StartsWith($directory+'\',[StringComparison]::OrdinalIgnoreCase) -or
            $directory.StartsWith($release+'\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Release, existing binaries and identity must be separate directories.' }
    }
    $currentRelease=$null
    if (Test-Path -LiteralPath $releaseMarker) {
        $currentRelease=Get-Content -LiteralPath $releaseMarker -Raw | ConvertFrom-Json
        if ([version]$manifest.version -le [version]$currentRelease.version) { throw 'Upgrade version must be newer than the installed package.' }
    }
    New-Item -ItemType Directory -Path $release | Out-Null
    Protect-EdgeRelease $release $ServiceName
    Copy-Item -LiteralPath (Join-Path $PackageDirectory 'bin/edge-core.exe') -Destination $release
    Get-ChildItem -LiteralPath (Join-Path $PackageDirectory 'bin') -Filter '*.dll' -File | Copy-Item -Destination $release
    foreach ($entry in $manifest.files | Where-Object {$_.path -like 'bin/*'}) {
        if ((Get-FileHash -LiteralPath (Join-Path $release ([IO.Path]::GetFileName($entry.path))) -Algorithm SHA256).Hash -ne $entry.sha256) {
            throw 'Staged binary integrity mismatch.'
        }
    }
    $candidate='"'+(Join-Path $release 'edge-core.exe')+'"'+$image.Groups['arguments'].Value
    $transaction=[ordered]@{schema=1; serviceName=$ServiceName; stage='Prepared';
        oldCommand=$service.PathName; newCommand=$candidate; wasRunning=($service.State -eq 'Running');
        httpPort=[int]$port.Groups['port'].Value; version=$manifest.version; startedUtc=[DateTime]::UtcNow.ToString('o');
        oldInstallation=($installation | ConvertTo-Json | ConvertFrom-Json); oldRelease=$currentRelease}
    $expectedIdentity=$null
    if ($RequireCloud) {
        if (-not $transaction.wasRunning -or $transaction.httpPort -eq 0) { throw 'Cloud qualification needs a running client with an HTTP status port.' }
        $status=Invoke-RestMethod -Uri "http://127.0.0.1:$($transaction.httpPort)/status" -TimeoutSec 3
        if ($status.status -ne 'connected') { throw 'Cloud qualification needs an initially connected client.' }
        $expectedIdentity=$status.'internal-id'
    }
    Write-Journal $transaction
    try {
        Stop-OwnedService
        if ((Service-Info).PathName -ne $transaction.oldCommand) { throw 'Service command changed before activation.' }
        Set-Command $candidate
        $transaction.stage='Switched'; Write-Journal $transaction
        if ($transaction.wasRunning) {
            Start-Service $ServiceName
            Wait-EdgeServiceReady $ServiceName $candidate $transaction.httpPort
        }
        if ($RequireCloud) {
            $deadline=[DateTime]::UtcNow.AddSeconds(150)
            do {
                $status=Invoke-RestMethod -Uri "http://127.0.0.1:$($transaction.httpPort)/status" -TimeoutSec 3
                if ($status.status -eq 'connected') { break }
                Start-Sleep -Seconds 1
            } while ([DateTime]::UtcNow -lt $deadline)
            if ($status.status -ne 'connected' -or $status.'internal-id' -ne $expectedIdentity) { throw 'Candidate failed cloud identity qualification.' }
        }
        $installation.installDirectory=$release
        $installation | ConvertTo-Json | Set-Content -LiteralPath $installationPath -Encoding UTF8
        @{version=$manifest.version; directory=$release; previousDirectory=$oldDirectory; schema=1} |
            ConvertTo-Json | Set-Content -LiteralPath $releaseMarker -Encoding UTF8
        $transaction.stage='Complete'; Write-Journal $transaction
    } catch {
        $failure=$_.Exception.Message
        try { Restore-Previous $transaction }
        catch { throw "Upgrade failed: $failure Rollback also failed: $($_.Exception.Message). Use -Action Recover with this service." }
        throw "Upgrade failed and previous binary path was restored: $failure"
    }
    Write-Output "Upgraded $ServiceName to $($manifest.version). Previous binaries, configuration and identity retained."
} finally { $lock.Dispose() }
