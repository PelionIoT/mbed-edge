# Native C named-pipe counter transport example

This standalone Windows client/server experiment uses Win32 APIs and the C
runtime. It has no Node or Edge dependency. The client sets and reads a counter
at 1001, 1002 and 1003 through a duplex, local-only named pipe.

It is a server transport test with a small command protocol. It does not use
the PT JSON-RPC API or verify cloud values. The production Windows PT SDK is on
the backlog; its supported client example will live in a separate repository, following
[the implementation plan](../../../docs/windows-pt-transports.md#native-c-prototype-and-implementation-plan).
For the implemented Edge Core PT listener and its JSON-RPC C test client, use
[NAMED-PIPE-PT.md](../NAMED-PIPE-PT.md).

## Build and run

From the repository root, with Visual Studio C++ Build Tools and CMake:

```powershell
cmake -S test/windows-core/named-pipe-example -B build/windows-named-pipe-example -A x64
cmake --build build/windows-named-pipe-example --config Debug
ctest --test-dir build/windows-named-pipe-example -C Debug --output-on-failure
cmake --build build/windows-named-pipe-example --config Release
ctest --test-dir build/windows-named-pipe-example -C Release --output-on-failure
```

The self-test spawns a temporary server process and selects a unique pipe name.
It checks split and combined length-prefixed records, a server-initiated message,
invalid commands, pending-read cancellation completion, duplicate-name/instance
creation denial, normal process exit and pipe-name reclamation. The two cases
use precise client rights and generic read/write client rights respectively.
Both must pass; this does not test Node, a different PT user or LocalService.

To run the server and client manually in two terminals:

```powershell
.\build\windows-named-pipe-example\Debug\named-pipe-counter-example.exe `
    --server '\\.\pipe\EdgeCounterExample'
```

```powershell
.\build\windows-named-pipe-example\Debug\named-pipe-counter-example.exe `
    --client '\\.\pipe\EdgeCounterExample'
```

Start the client within five seconds. The server accepts one client, receives
counter commands and a stop request, then observes client disconnect before
closing. All operations have five-second deadlines and retain I/O buffers until
completion, including after requesting cancellation. A failed check exits 1;
successful tests exit 0; incorrect arguments exit 2.

The example's explicit DACL permits data exchange only to the invoking user's
SID, excluding permission to create another server instance. A real service
needs separate server and client identity grants and actual restricted-service
qualification. Remote clients are rejected by configuration; a remote connection
has not been attempted. Both precise and generic C client opens succeeded on
the tested host; do not infer a Node failure from its requested access mask.

## Qualification on 2026-10-03

Windows 10 Pro 22H2 x64, build 19045.6466, MSVC 19.44.35229.0 and SDK 26100:
Debug 2/2 and Release 2/2 passed using the ordinary user token. The restricted
tool-token run received access denied at the pipe client open. Ordinary-token
tests kept the example's narrow DACL and did not alter machine/service ACLs.
Logs are under ignored `build/windows-named-pipe-example-*-normal-token-ctest.log`.
No test processes remain; the installed Edge service was not changed.

The source uses Vista-or-later cancellation/timing APIs. Its current binary and
runtime have only been tested on Windows 10. Windows 8 is an API-compatible
candidate needing its own build/runtime and OS qualification. XP requires
alternate APIs and a legacy toolchain; this example does not support XP.
