# SPDX-License-Identifier: Apache-2.0
# Run in an x64 Visual Studio developer environment with Perl on PATH.
[CmdletBinding()]
param(
    [string]$Version = '3.5.9',
    [string]$Sha256 = '603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a',
    [Parameter(Mandatory=$true)][string]$OutputDirectory
)
$ErrorActionPreference = 'Stop'
if ($Version -notmatch '^3\.\d+\.\d+$' -or $Sha256 -notmatch '^[a-fA-F0-9]{64}$') {
    throw 'Supply an OpenSSL 3 release version and its independently verified SHA-256.'
}
$root = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $root) { throw 'OutputDirectory must be new.' }
New-Item -ItemType Directory -Path $root | Out-Null
$archive = Join-Path $root "openssl-$Version.tar.gz"
Invoke-WebRequest -Uri "https://www.openssl.org/source/openssl-$Version.tar.gz" -OutFile $archive
if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash -ne $Sha256) {
    throw 'OpenSSL source checksum does not match the pinned release.'
}
& tar -xzf $archive -C $root
if ($LASTEXITCODE -ne 0) { throw 'OpenSSL source extraction failed.' }
$source = Join-Path $root "openssl-$Version"
$install = Join-Path $root 'install'
Push-Location $source
try {
    & perl Configure VC-WIN64A shared no-tests no-asm "--prefix=$install" "--openssldir=$install/ssl"
    if ($LASTEXITCODE -ne 0) { throw 'OpenSSL configuration failed.' }
    & nmake
    if ($LASTEXITCODE -ne 0) { throw 'OpenSSL compilation failed.' }
    & nmake install_sw
    if ($LASTEXITCODE -ne 0) { throw 'OpenSSL installation failed.' }
} finally { Pop-Location }
Write-Output "OpenSSL SDK: $install"
