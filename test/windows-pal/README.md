# Windows PAL smoke test

Run from PowerShell in the Edge repository root on x64 Windows:

```powershell
.\build-windows.ps1 -PalTests
```

This configures, builds and runs a native console test executable using CTest.
It needs Visual Studio 2022 C++ Build Tools, a Windows SDK, CMake and the
initialized cloud-client submodule. The helper locates Visual Studio's bundled
CMake when it is not on `PATH`. No administrator privileges, cloud credentials
or Internet connection are needed for the test. IPv4 and IPv6 loopback must be
enabled.

The test links the real Windows adapters and the existing generic PAL wrappers.
It checks threads, locks, semaphores, cancellation, timers, Unicode and binary
file I/O, TCP/UDP loopback, socket callbacks, localhost DNS, system entropy and
handle cleanup. Files are created in a uniquely named directory under the
build directory and removed on success. A failure can leave that test directory
for inspection. No service is installed and no host reboot is requested.

Success prints `100% tests passed`; the helper returns a nonzero exit code on a
configure, compile or test failure. CTest limits a run to 45 seconds and saves
details to `build/windows-pal/Testing/Temporary/LastTest.log`.

For an optimized build, or to compile the production PAL library targets:

```powershell
.\build-windows.ps1 -PalTests -Configuration Release
.\build-windows.ps1 -PalOnly
```

`-PalOnly` builds `palRTOS`, `palFilesystem`, `palNetworking` and `palDRBG` in
`build/windows-x64`. `-PalTests` uses a standalone project in `build/windows-pal`
so application code that has not been ported does not block the smoke test.
The two switches are mutually exclusive. `-BuildDirectory` overrides either
output directory.

To rerun without compiling, use `ctest` from `PATH` or the directory containing
the `cmake.exe` selected by the helper:

```powershell
ctest --test-dir build/windows-pal -C Debug --output-on-failure
ctest --test-dir build/windows-pal -C Debug --output-on-failure --repeat until-fail:50
```

Checks remain enabled in Release builds. Compiler warnings are errors for the
new platform sources and the test code; existing generic PAL wrappers retain
their current warnings. This suite does not test TLS, generic DRBG behavior,
cloud registration, provisioning or the eventual Windows service. It is not a
replacement for running the finished application across the supported OS matrix.
