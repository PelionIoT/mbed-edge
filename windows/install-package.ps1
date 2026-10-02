# SPDX-License-Identifier: Apache-2.0
# Headless offline install. No downloads, passwords or host restart.
[CmdletBinding()]
param(
    [string]$PackageDirectory=(Split-Path -Parent $PSScriptRoot),
    [ValidatePattern('^[A-Za-z0-9_.-]{1,80}$')][string]$ServiceName='EdgeCore',
    [string]$InstallRoot=(Join-Path $env:ProgramFiles 'Izuma/EdgeCore'),
    [string]$DataDirectory=(Join-Path $env:ProgramData 'Izuma/EdgeCore'),
    [string]$ProvisioningFile,
    [ValidateRange(0,65535)][int]$HttpPort=8080,
    [ValidateRange(1,65535)][int]$ProtocolPort=7681,
    [switch]$Start,
    [switch]$AllowUnsigned,
    [string]$SignerThumbprint
)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'package-tools.ps1')
Assert-EdgeAdministrator
$manifest=Test-EdgePackage $PackageDirectory -AllowUnsigned:$AllowUnsigned -SignerThumbprint $SignerThumbprint
if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) { throw 'Service already exists; use update-service.ps1.' }
$install=Get-EdgeLocalDirectory $InstallRoot
$data=Get-EdgeLocalDirectory $DataDirectory
$release=Join-Path $install ('releases/'+$manifest.version)
$runtime=Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64' -ErrorAction SilentlyContinue
$rebootRequired=$false
if (-not $runtime -or -not $runtime.Installed -or [version]$runtime.Version.TrimStart('v') -lt [version]$manifest.visualCppVersion) {
    $redist=Join-Path $PackageDirectory 'prerequisites/vc_redist.x64.exe'
    $signature=Get-AuthenticodeSignature -LiteralPath $redist
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') {
        throw 'The offline Visual C++ prerequisite is not Microsoft-signed.'
    }
    $process=Start-Process -FilePath $redist -ArgumentList @('/install','/quiet','/norestart') -WindowStyle Hidden -Wait -PassThru
    if ($process.ExitCode -notin @(0,3010)) { throw "Visual C++ prerequisite failed: $($process.ExitCode)." }
    $rebootRequired=$process.ExitCode -eq 3010
}
$arguments=@{BinaryDirectory=(Join-Path $PackageDirectory 'bin'); ServiceName=$ServiceName;
    InstallDirectory=$release; DataDirectory=$data; HttpPort=$HttpPort; ProtocolPort=$ProtocolPort; Start=$Start}
if ($ProvisioningFile) { $arguments.ProvisioningFile=$ProvisioningFile }
& (Join-Path $PSScriptRoot 'install-service.ps1') @arguments
@{schema=1; version=$manifest.version; directory=$release; previousDirectory=$null} |
    ConvertTo-Json | Set-Content -LiteralPath (Join-Path $data 'service-release.json') -Encoding UTF8
Write-Output "Installed package $($manifest.version). Reboot required by prerequisite: $rebootRequired. No restart was requested."
if ($rebootRequired) { exit 3010 }
