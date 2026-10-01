# SPDX-License-Identifier: Apache-2.0
# Run elevated. Test existing private bundles; never reset retained identities.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$BuildDirectory,
    [Parameter(Mandatory=$true)][string]$CredentialDirectory,
    [Parameter(Mandatory=$true)][string]$OutputDirectory,
    [switch]$OfflineStartup
)
$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this integration matrix from an elevated PowerShell prompt.'
}
$build = (Resolve-Path -LiteralPath $BuildDirectory).Path
$credentials = (Resolve-Path -LiteralPath $CredentialDirectory).Path
$cache = Get-Content -LiteralPath (Join-Path $build 'CMakeCache.txt') -Raw
foreach ($option in @('BYOC_MODE:BOOL=ON','DEVELOPER_MODE:BOOL=OFF','MBED_CLOUD_CLIENT_USE_OPENSSL:BOOL=ON')) {
    if ($cache -notmatch ('(?m)^' + [regex]::Escape($option) + '\r?$')) {
        throw "BuildDirectory must use $option; this matrix requires runtime provisioning with OpenSSL."
    }
}
$out = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $out) { throw 'OutputDirectory must be new.' }
foreach ($configuration in @('Release','Debug')) {
    foreach ($executable in @('edge-core.exe','windows-service-probe.exe')) {
        if (-not (Test-Path -LiteralPath (Join-Path $build "bin/$configuration/$executable") -PathType Leaf)) {
            throw "Missing $configuration/$executable; build the BYOC profile with -CoreTests."
        }
    }
}
foreach ($format in @('cbor','json')) {
    if (-not (Test-Path -LiteralPath (Join-Path $credentials "provisioning.$format") -PathType Leaf)) {
        throw "Missing provisioning.$format in CredentialDirectory."
    }
}
New-Item -ItemType Directory -Path $out | Out-Null
# Results contain imported identities/private provisioning copies. Restrict the
# matrix root before the production installer creates its per-service ACLs.
$acl = New-Object Security.AccessControl.DirectorySecurity
$acl.SetAccessRuleProtection($true,$false)
foreach ($sid in @('S-1-5-18','S-1-5-32-544')) {
    $rule = New-Object Security.AccessControl.FileSystemAccessRule(
        ([Security.Principal.SecurityIdentifier]$sid),'FullControl','ContainerInherit,ObjectInherit','None','Allow')
    $acl.AddAccessRule($rule)
}
$rule = New-Object Security.AccessControl.FileSystemAccessRule(
    $identity.User,'FullControl','ContainerInherit,ObjectInherit','None','Allow')
$acl.AddAccessRule($rule)
Set-Acl -LiteralPath $out -AclObject $acl
$results = [ordered]@{passed=$false; cases=@(); error=$null; offlineStartup=[bool]$OfflineStartup}
try {
    foreach ($configuration in @('Release','Debug')) {
        foreach ($format in @('cbor','json')) {
            $caseDirectory = Join-Path $out ($configuration.ToLowerInvariant() + '-' + $format)
            $caseFailure = $null
            try {
                & (Join-Path $PSScriptRoot 'test-service.ps1') `
                    -BinaryDirectory (Join-Path $build "bin/$configuration") `
                    -OutputDirectory $caseDirectory -RealCloud -OfflineStartup:$OfflineStartup `
                    -ProvisioningFile (Join-Path $credentials "provisioning.$format")
            } catch { $caseFailure = $_.Exception.Message }
            $case = Get-Content -LiteralPath (Join-Path $caseDirectory 'results.json') -Raw | ConvertFrom-Json
            $results.cases += [ordered]@{
                configuration=$configuration; format=$format; passed=$case.passed
                cloudIdentity=$case.cloudIdentity; evidenceDirectory=$caseDirectory
                checks=$case.checks; error=$case.error
            }
            if (-not $case.passed -or $caseFailure) { throw "$configuration/$format failed; inspect its retained evidence." }
        }
    }
    $results.passed = $true
} catch {
    $results.error = $_.Exception.Message
} finally {
    $results | ConvertTo-Json -Depth 7 | Set-Content -LiteralPath (Join-Path $out 'results.json')
}
if (-not $results.passed) { throw $results.error }
