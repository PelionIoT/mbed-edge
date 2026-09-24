# Native Windows build experiment

This is an incomplete port. The Windows PAL adapters now compile as native
MSVC x64 libraries and pass focused runtime tests through the existing PAL
interfaces. The full application does not yet build or install as a service.

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
The helper defaults to one MSBuild worker. Increase this with `-Jobs` on hosts
where parallel MSBuild works correctly. This build environment failed to
coordinate parallel workers; a single worker produces normal compiler errors.

The helper normalizes duplicate `Path`/`PATH` environment entries in the child
process. Without this, some launchers cause MSBuild's compiler detection to
fail with a duplicate dictionary-key error even with a valid MSVC installation.

## Initial result

The attempt on 2026-09-24 used MSVC 19.44.35229, CMake 3.31.6, and the Windows
10.0.26100.0 SDK. C and C++ compiler detection succeeded, and an x64 compiler
probe compiled and linked successfully. After the build-configuration fixes,
`build-windows.ps1 -ConfigureOnly` completed configuration but failed generation
with exit code 1 because these PAL source files were absent:

```text
OS_Specific/Windows/Board_Specific/TARGET_x86_x64/pal_plat_x86_x64.c
OS_Specific/Windows/Storage/FileSystem/pal_plat_fileSystem.c
OS_Specific/Windows/Networking/pal_plat_network.c
```

CMake consequently could not generate the `palRTOS`, `palFilesystem`, and
`palNetworking` targets. The RTOS implementation file was also required by the
source list. The initial configure log is `build/windows-configure-retry.log`.
The PAL work described below resolves that generation failure. Linux regression
validation has not been run on this host.

## Porting boundary

Keep operating-system changes in Windows-specific files or platform guards.
Use the existing cloud-client PAL contracts and its `ns-hal-pal` event loop.
The selected `OS_BRAND=Windows` now selects implementations under
`mbed-client-pal/Source/Port/Reference-Impl/OS_Specific/Windows`. The cloud-client
submodule has a matching local `experiment/win10support` branch for these
changes. Preserve both repositories' changes when committing this stage.

## PAL implementation and validation

The implementations provide native threads, recursive mutexes, semaphores,
one-shot/periodic timers, monotonic ticks, system entropy, UTF-8 filesystem
paths, and IPv4/IPv6 Winsock UDP/TCP sockets. DNS uses the existing PAL
asynchronous worker around the Windows resolver. Windows uses the `default`
network interface profile and delegates routing to the OS.

The production CMake targets `palRTOS`, `palFilesystem`, `palNetworking`, and
`palDRBG` build successfully. Build these libraries independently of the
remaining application port with:

```powershell
.\build-windows.ps1 -PalOnly
```

The standalone runtime suite passed in Debug and Release on 2026-09-24.
Run it with:

```powershell
.\build-windows.ps1 -PalTests
.\build-windows.ps1 -PalTests -Configuration Release
```

The suite compiles the actual platform implementations and generic PAL wrappers.
It exercises contention, cancellation, timers and callback deletion, binary file
I/O, Unicode paths, exclusive creation, copy/delete behavior, socket callbacks,
IPv4/IPv6 loopback UDP/TCP, listen/accept, DNS, entropy, and handle cleanup.
Short one-shot timers also cover a lost-wakeup bug found during repeated runs.
The suite tests the native entropy hook; it does not yet exercise the generic
DRBG or TLS at runtime. These are local Windows 10 tests; Server and Windows 11
validation remains. See [the smoke-test instructions](../test/windows-pal/README.md)
for prerequisites, test output and rerunning without recompiling.

Current limitations:

- Thread termination is a cooperative cancellation request observed at PAL
  waits/delays. Application loops must cooperate; arbitrary threads are not
  forcibly terminated.
- Timer stop prevents future firings but an already dispatched callback may
  finish. Deletion from another thread waits for that callback; callers must
  not hold locks required by the callback.
- Native socket event callbacks require nonblocking sockets. Blocking sockets
  without callbacks are supported. Explicit adapter binding, connection-status
  callbacks, DNS API 2/3 and IPv6 traffic-class options are not implemented.
- The current PAL `off_t` is 32-bit with MSVC. Position results that cannot fit
  are rejected rather than truncated. Large-file support needs an API decision
  before firmware update support.
- Flat folder operations preserve subdirectories. Formatting Windows volumes
  and changing the host clock are not supported. The reboot hook exits only
  the process; host reboot needs the later privileged updater and policy.

## Remaining application build work

CMake now generates the application project. Building it exposes further
MSVC incompatibilities in cloud-client headers (GNU attributes and array
parameter declarations) and POSIX
dependencies in edge-core, including `pthread.h`, `unistd.h`, `sys/socket.h`,
`sys/file.h`, and `arpa/inet.h`. Linux link names such as `pthread`, `rt`, and
`stdc++` also still need platform guards. Logs from this stage are under
`build/windows-pal-full-build.log` and `build/windows-msbuild-diagnostic.log`.
The bundled libwebsockets/libevent adapter also emits Windows x64 socket-handle
truncation and pointer/integer warnings that need review before translator
runtime validation.

Windows branches for edge-core and translator SDK calls are the next step.
Disabling libwebsockets' Unix-socket build option does not itself implement the
planned authenticated local Windows transport.

After a working console build, add SCM lifecycle handling, the restricted
service identity, logging, and offline/headless installer packaging. Service,
cloud-bootstrap, provisioning, and translator runtime validation have not yet
been performed. Firmware updating and privileged reboot handling remain later
work.
