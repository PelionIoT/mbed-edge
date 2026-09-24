# Native Windows build experiment

This is an incomplete port. The Windows build configuration selects MSVC x64
and the cloud client's existing PAL interfaces, but it does not yet produce
an `edge-core.exe` or install a Windows service.

## Source baseline

`experiment/win10support` was created from local `master` at
`64e615230f467fb42fc29730a8f0acd71ca4bcaf`; this repository has no local `main`
branch. The initial build attempt uses that baseline, including its existing
mbedTLS backend. The OpenSSL requirement remains outstanding: integrate the
edge `feature/openssl_support` work and the matching cloud-client revision
before validating the intended Windows TLS build.

## Reproduce the initial attempt

Prerequisites are Visual Studio 2022 C++ Build Tools, a Windows SDK, CMake, and
the repository's initialized submodules. The helper can locate CMake bundled
with Visual Studio when it is absent from `PATH`.

From PowerShell at the repository root:

```powershell
.\build-windows.ps1 -ConfigureOnly
.\build-windows.ps1 -Configuration Debug
```

The default output directory is `build/windows-x64`. The helper selects BYOC
provisioning and disables firmware updates and documentation for this initial
attempt. These are development settings, not a reduced final feature scope.
Custom CMake arguments can be passed with `-CMakeArgument`.

The helper normalizes duplicate `Path`/`PATH` environment entries in the child
process. Without this, some launchers cause MSBuild's compiler detection to
fail with a duplicate dictionary-key error even with a valid MSVC installation.

## Initial result

The attempt on 2026-09-24 used MSVC 19.44.35229, CMake 3.31.6, and the Windows
10.0.26100.0 SDK. C and C++ compiler detection succeeded, and an x64 compiler
probe compiled and linked successfully. After the build-configuration fixes,
`build-windows.ps1 -ConfigureOnly` completed configuration but failed generation
with exit code 1 because these PAL source files are absent:

```text
OS_Specific/Windows/Board_Specific/TARGET_x86_x64/pal_plat_x86_x64.c
OS_Specific/Windows/Storage/FileSystem/pal_plat_fileSystem.c
OS_Specific/Windows/Networking/pal_plat_network.c
```

CMake consequently cannot generate the `palRTOS`, `palFilesystem`, and
`palNetworking` targets. The RTOS implementation file is also required by the
source list. The local final configure log is
`build/windows-configure-retry.log`. Application compilation and runtime tests
have not started; Linux regression validation has not been run on this host.

## Porting boundary

Keep operating-system changes in Windows-specific files or platform guards.
Use the existing cloud-client PAL contracts and its `ns-hal-pal` event loop.
The selected `OS_BRAND=Windows` currently has no implementation directory under
`mbed-client-pal/Source/Port/Reference-Impl/OS_Specific`.

The next required platform work is:

- PAL RTOS primitives, timers, and platform hooks for x64 Windows.
- PAL filesystem operations and asynchronous networking over Winsock.
- MSVC support in common PAL headers and compiler flags.
- Windows branches for edge-core and translator SDK POSIX calls.
- Local translator transport: disabling libwebsockets' Unix-socket build option
  does not itself implement the planned local Windows transport.

After a working console build, add SCM lifecycle handling, the restricted
service identity, logging, and offline/headless installer packaging. Service,
cloud-bootstrap, provisioning, and translator runtime validation have not yet
been performed. Firmware updating and privileged reboot handling remain later
work.
