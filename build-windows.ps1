# Build tools run on the developer machine; the application remains native Win32.
[CmdletBinding(DefaultParameterSetName = 'Edge')]
param(
    [string]$BuildDirectory = (Join-Path $PSScriptRoot 'build/windows-x64'),
    [ValidateSet('Debug', 'Release', 'RelWithDebInfo')]
    [string]$Configuration = 'Debug',
    [string]$CMakePath,
    [switch]$ConfigureOnly,
    [Parameter(ParameterSetName = 'PalTests')]
    [switch]$PalTests,
    [Parameter(ParameterSetName = 'PalBuild')]
    [switch]$PalOnly,
    [ValidateRange(1, 64)]
    [int]$Jobs = 1,
    [string[]]$CMakeArgument = @()
)

$ErrorActionPreference = 'Stop'
if (-not $CMakePath) {
    $cmakeCommand = Get-Command cmake -ErrorAction SilentlyContinue
    if ($cmakeCommand) {
        $CMakePath = $cmakeCommand.Source
    } else {
        $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio/Installer/vswhere.exe'
        if (-not (Test-Path -LiteralPath $vswhere)) {
            throw 'Install Visual Studio 2022 C++ Build Tools and CMake, or specify -CMakePath.'
        }
        $installation = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
        if (-not $installation) { throw 'Visual Studio C++ Build Tools were not found.' }
        $CMakePath = Join-Path $installation 'Common7/IDE/CommonExtensions/Microsoft/CMake/CMake/bin/cmake.exe'
    }
}
if (-not (Test-Path -LiteralPath $CMakePath)) { throw "CMake was not found: $CMakePath" }

function Invoke-EdgeCMake {
    param([string[]]$Arguments)
    # Some launchers supply both Path and PATH. Normalize these before MSBuild
    # constructs its case-insensitive environment dictionary. Only the child
    # environment is changed; the user's machine environment is untouched.
    & $CMakePath -E env --unset=Path --unset=PATH "Path=$env:PATH" MSBUILDDISABLENODEREUSE=1 $CMakePath @Arguments
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

$sourceDirectory = $PSScriptRoot
$buildTargets = @('edge-core')
$profileArguments = @(
    '-DTARGET_TOOLCHAIN=mcc-windows-x64', '-DBYOC_MODE=ON', '-DDEVELOPER_MODE=OFF',
    '-DFIRMWARE_UPDATE=OFF', '-DFOTA_ENABLE=OFF', '-DBUILD_DOCUMENTATION=OFF'
)
if ($PalOnly) {
    $buildTargets = @('palRTOS', 'palFilesystem', 'palNetworking', 'palDRBG')
}
if ($PalTests) {
    $sourceDirectory = Join-Path $PSScriptRoot 'test/windows-pal'
    $buildTargets = @('windows-pal-tests')
    $profileArguments = @()
    if (-not $PSBoundParameters.ContainsKey('BuildDirectory')) {
        $BuildDirectory = Join-Path $PSScriptRoot 'build/windows-pal'
    }
}
$configureArguments = @(
    '-S', $sourceDirectory, '-B', $BuildDirectory,
    '-G', 'Visual Studio 17 2022', '-A', 'x64'
) + $profileArguments + $CMakeArgument
Invoke-EdgeCMake -Arguments $configureArguments
if (-not $ConfigureOnly) {
    $buildArguments = @('--build', $BuildDirectory, '--config', $Configuration, '--target') +
        $buildTargets + @('--parallel', "$Jobs")
    Invoke-EdgeCMake -Arguments $buildArguments
    if ($PalTests) {
        $ctestPath = Join-Path (Split-Path -Parent $CMakePath) 'ctest.exe'
        & $ctestPath --test-dir $BuildDirectory -C $Configuration --output-on-failure
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    }
}
