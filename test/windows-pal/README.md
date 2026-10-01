# Windows PAL smoke test

Run from PowerShell in the Edge repository root on x64 Windows:

```powershell
$openssl = 'C:/path/to/native-openssl-sdk'
.\build-windows.ps1 -PalTests -OpenSSLRoot $openssl
```

This configures, builds and runs native console test executables using CTest.
It needs Visual Studio 2022 C++ Build Tools, a Windows SDK, CMake 3.22 or newer,
an x64 OpenSSL 3.x development SDK and the initialized cloud-client submodule.
The helper locates Visual Studio's bundled
CMake when it is not on `PATH`. No administrator privileges, cloud credentials
or Internet connection are needed for the test. IPv4 and IPv6 loopback must be
enabled.

The runtime test links the real Windows adapters and existing generic PAL wrappers.
It checks threads, locks, semaphores, cancellation, timers, Unicode and binary
file I/O, TCP/UDP loopback, socket callbacks, localhost DNS, system entropy and
handle cleanup. Files are created in a uniquely named directory under the
build directory and removed on success. A failure can leave that test directory
for inspection. No service is installed and no host reboot is requested.

The suite also compiles the shared upstream OpenSSL TLS and crypto sources.
The TLS test generates an in-memory certificate and runs a local TLS 1.2 server
restricted to the Windows cloud default, ECDHE-ECDSA-AES128-GCM-SHA256:
it checks trusted and untrusted handshakes, mutual client-certificate
authentication, nonblocking retries, encrypted echo and retention of the
caller's PAL socket after TLS cleanup. The crypto test
checks SHA-256 and HMAC-SHA-256 known vectors and OpenSSL random generation.
The Root of Trust test supplies KCM path metadata and checks the actual reader
using Windows PAL files, including UTF-8 paths and invalid/short/missing inputs.
The fifth test exercises Edge's real Windows common utilities: mutex modes and
contention, clocks, formatting/tokenization, exclusive file locks and binary
CBOR reads. The filesystem checks include opening a file under a missing
parent directory, as ESFS does on first startup.

TLS and crypto fixtures supply only the legacy entropy hook; the TLS fixture
also supplies an unused event-loop cancellation hook. The KCM store and full
application event loop are outside this suite. OpenSSL itself, certificate
verification, the shared backends and Windows adapters are real implementations.

Success prints `100% tests passed`; the helper returns a nonzero exit code on a
configure, compile or test failure. CTest limits a run to 45 seconds and saves
details to `build/windows-pal/Testing/Temporary/LastTest.log`.

For an optimized build, or to compile the production PAL library targets:

```powershell
.\build-windows.ps1 -PalTests -Configuration Release -OpenSSLRoot $openssl
.\build-windows.ps1 -PalOnly -OpenSSLRoot $openssl
```

`-PalOnly` builds `palRTOS`, `palFilesystem`, `palNetworking`, `palDRBG` and
the shared `crypto-service` in
`build/windows-x64`. `-PalTests` uses a standalone project in `build/windows-pal`
to test the PAL and common utilities independently of the application.
The two switches are mutually exclusive. `-BuildDirectory` overrides either
output directory.

`-OpenSSLRoot` becomes `OPENSSL_ROOT_DIR`. When the SDK has shared DLLs in
`bin`, CTest adds that directory to the OpenSSL test processes' PATH.
To run just the runtime and Root of Trust checks before an SDK is available:

```powershell
.\build-windows.ps1 -PalTests -CMakeArgument '-DWINDOWS_PAL_TEST_TLS=OFF'
```

Re-enable the option with `-CMakeArgument '-DWINDOWS_PAL_TEST_TLS=ON'` in that
build directory to restore TLS and crypto tests. The production Windows build
selects OpenSSL independently of this test option.

To rerun without compiling, use `ctest` from `PATH` or the directory containing
the `cmake.exe` selected by the helper:

```powershell
ctest --test-dir build/windows-pal -C Debug --output-on-failure
```

Checks remain enabled in Release builds. Compiler warnings are errors for the
new platform sources and the test code; existing generic PAL wrappers and
shared OpenSSL backends retain their current warnings. This suite does not
test generic DRBG state management,
cloud registration, provisioning or the eventual Windows service. It is not a
replacement for running the finished application across the supported OS matrix.
For actual executable startup and native WebSocket transport checks, use
[`-CoreTests`](../windows-core/README.md).
