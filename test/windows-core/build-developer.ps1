# Build the existing developer provisioning flow with a downloaded C credential.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$CredentialFile,
    [string]$OpenSSLRoot,
    [ValidateSet('Debug', 'Release', 'RelWithDebInfo')]
    [string]$Configuration = 'Debug',
    [string]$BuildDirectory,
    [string]$CMakePath
)
$ErrorActionPreference = 'Stop'
$repoDirectory = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$credentialPath = (Resolve-Path -LiteralPath $CredentialFile).Path
if (-not (Test-Path -LiteralPath $credentialPath -PathType Leaf)) {
    throw 'CredentialFile must be the downloaded mbed_cloud_dev_credentials.c file.'
}
$credentialSource = [System.IO.File]::ReadAllText($credentialPath)
foreach ($field in @('BOOTSTRAP_ENDPOINT_NAME', 'BOOTSTRAP_SERVER_URI',
                    'BOOTSTRAP_DEVICE_CERTIFICATE', 'BOOTSTRAP_DEVICE_CERTIFICATE_SIZE',
                    'BOOTSTRAP_DEVICE_PRIVATE_KEY', 'BOOTSTRAP_DEVICE_PRIVATE_KEY_SIZE',
                    'BOOTSTRAP_SERVER_ROOT_CA_CERTIFICATE', 'BOOTSTRAP_SERVER_ROOT_CA_CERTIFICATE_SIZE',
                    'MANUFACTURER', 'MODEL_NUMBER', 'SERIAL_NUMBER', 'DEVICE_TYPE',
                    'HARDWARE_VERSION', 'MEMORY_TOTAL_KB')) {
    if ($credentialSource -notmatch ('\bMBED_CLOUD_DEV_' + $field + '\b')) {
        throw "Downloaded C credential is missing MBED_CLOUD_DEV_$field."
    }
}
$credentialSource = $null
if (-not $BuildDirectory) {
    $BuildDirectory = Join-Path $repoDirectory 'build/windows-cloud-connectivity/build-dev'
}
$buildParameters = @{
    CoreTests = $true
    BuildDirectory = $BuildDirectory
    Configuration = $Configuration
    CMakeArgument = @('-DBYOC_MODE=OFF', '-DDEVELOPER_MODE=ON', '-DROT_FROM_FILE=OFF',
                      '-DTRACE_LEVEL=DEBUG', '-DTRACE_COAP_PAYLOAD=OFF',
                      "-DMBED_CLOUD_IDENTITY_CERT_FILE=$($credentialPath.Replace('\', '/'))",
                      '-DCMAKE_POLICY_VERSION_MINIMUM=3.5')
}
if ($OpenSSLRoot) { $buildParameters.OpenSSLRoot = $OpenSSLRoot }
if ($CMakePath) { $buildParameters.CMakePath = $CMakePath }
& (Join-Path $repoDirectory 'build-windows.ps1') @buildParameters
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Write-Output "Developer executable: $BuildDirectory/bin/$Configuration/edge-core.exe"
Write-Output 'Start it from an isolated working directory to keep each test identity separate.'
