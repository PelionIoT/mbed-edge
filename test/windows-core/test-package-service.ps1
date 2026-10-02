# SPDX-License-Identifier: Apache-2.0
# Elevated real-cloud upgrade/rollback test. Creates only owned test services.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$InitialPackage,
    [Parameter(Mandatory=$true)][string]$UpgradePackage,
    [Parameter(Mandatory=$true)][string]$FailureExecutable,
    [Parameter(Mandatory=$true)][string]$ProvisioningFile,
    [Parameter(Mandatory=$true)][string]$OutputDirectory
)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot '../../windows/package-tools.ps1')
Assert-EdgeAdministrator
$out=Get-EdgeLocalDirectory ([IO.Path]::GetFullPath($OutputDirectory))
if (Test-Path -LiteralPath $out) { throw 'OutputDirectory must be new.' }
New-Item -ItemType Directory -Path $out | Out-Null
$name='IzumaEdgeUpgrade_'+[Guid]::NewGuid().ToString('N').Substring(0,12)
$data=Join-Path $out 'service data'; $install=Join-Path $out 'installation'
$result=[ordered]@{passed=$false; checks=@(); cloudIdentity=$null; error=$null}
function Record { param([string]$Text); $result.checks+=$Text; $Text | Add-Content -LiteralPath (Join-Path $out 'progress.log') }
function Free-Port { $listener=New-Object Net.Sockets.TcpListener([Net.IPAddress]::Loopback,0); $listener.Start(); $port=$listener.LocalEndpoint.Port; $listener.Stop(); return $port }
function Wait-Cloud {
    $deadline=[DateTime]::UtcNow.AddSeconds(150)
    do {
        if ((Get-Service $name).Status -ne 'Running') { throw 'Test service exited.' }
        try { $status=Invoke-RestMethod -Uri "http://127.0.0.1:$http/status" -TimeoutSec 3; if ($status.status -eq 'connected') { return $status.'internal-id' } } catch { }
        Start-Sleep -Seconds 1
    } while ([DateTime]::UtcNow -lt $deadline)
    throw 'Test client did not register.'
}
$http=Free-Port; do { $pt=Free-Port } while ($pt -eq $http)
try {
    & (Join-Path $InitialPackage 'scripts/install-package.ps1') -PackageDirectory $InitialPackage `
        -ServiceName $name -InstallRoot $install -DataDirectory $data -ProvisioningFile $ProvisioningFile `
        -HttpPort $http -ProtocolPort $pt -AllowUnsigned -Start
    $identity=Wait-Cloud; $result.cloudIdentity=$identity
    Record 'Offline payload installation, prerequisite version check and cloud registration as restricted LocalService passed'
    $provision=Join-Path $data ('config/provisioning'+[IO.Path]::GetExtension($ProvisioningFile))
    Move-Item -LiteralPath $provision -Destination ($provision+'.test-withheld')
    $upgradeManifest=Test-EdgePackage $UpgradePackage -AllowUnsigned
    $release=Join-Path $install ('releases/'+$upgradeManifest.version)
    & (Join-Path $UpgradePackage 'scripts/update-service.ps1') -ServiceName $name -PackageDirectory $UpgradePackage `
        -ReleaseDirectory $release -AllowUnsigned -RequireCloud
    if ((Wait-Cloud) -ne $identity) { throw 'Upgrade changed cloud identity.' }
    $service=Get-CimInstance Win32_Service -Filter "Name='$name'"
    if (-not $service.PathName.StartsWith('"'+(Join-Path $release 'edge-core.exe')+'"')) { throw 'Service did not activate the staged release.' }
    Record 'Versioned upgrade passed local readiness and reconnected with the same persisted cloud identity'
    $currentCommand=$service.PathName
    $downgradeRejected=$false
    try {
        & (Join-Path $UpgradePackage 'scripts/update-service.ps1') -ServiceName $name -PackageDirectory $InitialPackage `
            -ReleaseDirectory (Join-Path $install 'releases/rejected-downgrade') -AllowUnsigned
    } catch { $downgradeRejected=$_.Exception.Message -like 'Upgrade version must be newer*' }
    if (-not $downgradeRejected -or (Get-CimInstance Win32_Service -Filter "Name='$name'").PathName -ne $currentCommand) {
        throw 'Downgrade was not rejected before service mutation.'
    }
    Record 'Downgrade rejected without stopping or modifying the active service'
    $failurePackage=Join-Path $out 'failure-package'
    Copy-Item -LiteralPath $UpgradePackage -Destination $failurePackage -Recurse
    Copy-Item -LiteralPath $FailureExecutable -Destination (Join-Path $failurePackage 'bin/edge-core.exe') -Force
    $manifestPath=Join-Path $failurePackage 'package.json'
    $failureManifest=Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    $version=[version]$upgradeManifest.version
    $failureManifest.version='{0}.{1}.{2}' -f $version.Major,$version.Minor,($version.Build+1)
    $entry=$failureManifest.files | Where-Object {$_.path -eq 'bin/edge-core.exe'}
    $entry.bytes=(Get-Item -LiteralPath $FailureExecutable).Length
    $entry.sha256=(Get-FileHash -LiteralPath $FailureExecutable -Algorithm SHA256).Hash
    $utf8=New-Object Text.UTF8Encoding($false)
    [IO.File]::WriteAllText($manifestPath,($failureManifest | ConvertTo-Json -Depth 5),$utf8)
    Remove-Item -LiteralPath (Join-Path $failurePackage 'package.cat')
    New-FileCatalog -Path $failurePackage -CatalogFilePath (Join-Path $failurePackage 'package.cat') -CatalogVersion 2 | Out-Null
    $rolledBack=$false
    try {
        & (Join-Path $UpgradePackage 'scripts/update-service.ps1') -ServiceName $name -PackageDirectory $failurePackage `
            -ReleaseDirectory (Join-Path $install 'releases/failed-candidate') -AllowUnsigned -RequireCloud
    } catch { $rolledBack=$_.Exception.Message -like 'Upgrade failed and previous binary path was restored*' }
    $journal=Get-Content -LiteralPath (Join-Path $data 'service-update.json') -Raw | ConvertFrom-Json
    $marker=Get-Content -LiteralPath (Join-Path $data 'service-release.json') -Raw | ConvertFrom-Json
    if (-not $rolledBack -or $journal.stage -ne 'RolledBack' -or $marker.version -ne $upgradeManifest.version -or
        (Get-CimInstance Win32_Service -Filter "Name='$name'").PathName -ne $currentCommand -or (Wait-Cloud) -ne $identity) {
        throw 'Failed startup did not restore the previous running release and identity.'
    }
    Record 'Actual SCM candidate startup failure rolled back binary path/version and restored the same cloud identity'
    $result.passed=$true
} catch { $result.error=$_.Exception.Message; $_ | Out-String | Set-Content -LiteralPath (Join-Path $out 'failure.log') }
finally {
    try {
        & (Join-Path $InitialPackage 'scripts/install-service.ps1') -Action Uninstall -ServiceName $name
        if (Get-Service $name -ErrorAction SilentlyContinue) { throw 'Owned test service remained registered.' }
        if (-not (Test-Path -LiteralPath (Join-Path $data 'state/mcc_config'))) { throw 'Uninstall removed identity state.' }
        Record 'Uninstall removed only the test service and retained identity/configuration/logs'
    } catch { $result.passed=$false; $result.error+=" Cleanup: $($_.Exception.Message)" }
    $result | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $out 'results.json')
}
if (-not $result.passed) { throw $result.error }
