# Native Windows named-pipe PT transport

Edge Core accepts local PT JSON-RPC over Win32 duplex byte pipes. The server
transport belongs in `mbed-edge`. The separate Windows PT SDK remains on the
backlog; the C counter executable here is a small transport test client.

## Build selection

The Windows CMake profile defaults `EDGE_WINDOWS_NAMED_PIPE=ON`. To omit the
listener and its test/client targets, configure with:

```powershell
cmake -S . -B build/windows-x64 -DEDGE_WINDOWS_NAMED_PIPE=OFF
```

With the flag OFF, runtime settings with `namedPipe.enabled: true` fail before
cloud initialization. Disabled pipe settings remain valid. Named pipes do not
depend on Winsock AF_UNIX availability or its Windows build threshold. This
does not extend the supported OS list to Windows 8 or XP.

## Runtime settings and TCP isolation

Settings are read at startup through `--config <file>` and require a restart to
apply changes. They are separate from cloud provisioning JSON/CBOR. The default
is TCP enabled, AF_UNIX disabled and named pipes disabled.

For a pipe-only PT endpoint:

```json
{
  "schemaVersion": 1,
  "pt": {
    "tcpEnabled": false,
    "namedPipe": {
      "enabled": true,
      "name": "\\\\.\\pipe\\IzumaEdgeCorePT",
      "maxClients": 16,
      "clientSids": []
    }
  }
}
```

The pipe name must use the local `\\.\pipe\` prefix and an ASCII suffix of
letters, digits, dots, hyphens or underscores, fitting 255 bytes. Choose a
different name for each installation/instance. `maxClients` defaults to 16
and accepts 1–32. Up to 16 distinct numeric SID strings can be listed in
`clientSids`; use the actual intended PT user/group SIDs for service deployment.
Unknown keys, invalid types, duplicate keys and invalid values fail startup.

An empty `clientSids` grants access only to the server identity. In a console
run, that is the process user, so a C PT running as the same user can connect.
For a service, it is the enabled per-service SID; explicitly list the intended
PT identities before expecting an interactive PT to connect. The service SID
receives the server rights needed for multiple instances. Configured clients
receive data read/write rights without `FILE_CREATE_PIPE_INSTANCE`. The owner
rights entry suppresses implicit owner access to change the DACL. The server
identity retains full control; a PT using that same identity has those rights
too. No client impersonation or extra service privilege is required.
[Microsoft pipe security guidance](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights)

Every instance rejects remote pipe clients. The initial instance requires
`FILE_FLAG_FIRST_PIPE_INSTANCE`, and its handle remains owned until listener
shutdown. Connections reuse existing server handles, including after malformed
input or disconnect, so the listener does not release ownership between PTs.
The explicit allowlist limits local access; first-instance ownership alone
does not authenticate the server to a client if an unrelated process claims
the name before Edge starts.

`tcpEnabled: false` creates no TCP WebSocket listening socket. A CLI
`--edge-pt-address` overrides the configured address only; it cannot enable
TCP. AF_UNIX and named pipes can be enabled independently or together. With
AF_UNIX enabled, the existing WebSocket context adopts native AF_UNIX sockets
even when its TCP listener is disabled. All PT listeners may be disabled.

The TCP WebSocket endpoint also routes its management/GRM URLs; disabling the
listener removes those TCP paths too. The separate HTTP status server and
outbound cloud TCP/TLS connection are controlled by their existing settings.

## Pipe wire contract, version 1

Each record is a four-byte unsigned big-endian payload byte length followed by
one UTF-8 JSON document. Length must be 1–65536. Embedded NUL bytes are rejected.
Readers must assemble partial headers/bodies and accept consecutive records.
There is no HTTP upgrade or WebSocket framing on this pipe.

The client's first record must be exactly:

```json
{"protocol":"edge-pt","version":1}
```

The server validates the contract, opens a PT connection and replies:

```json
{"protocol":"edge-pt","version":1,"maxFrameSize":65536}
```

Unsupported versions, duplicate or extra handshake keys and malformed records
close the connection. After the reply, send the existing `jsonrpc: "2.0"` PT
messages, beginning with `protocol_translator_register`. Device registration,
resource values/operations, RPC IDs, errors and server-originated PT requests
use the existing PT API. The listener serves PT clients only; no URL selects
management or GRM on it. Client close is a handle disconnect.

## I/O and lifecycle

The listener uses overlapped accept/read/write operations with separate events
and buffers. A persistent libevent timer checks completion every 10 ms; it
never waits for client data in the normal event callback. Up to four read and
four write completions per client are processed per callback, with rotating
client order. Registration, RPC callbacks and teardown remain on the Edge
event thread. This backend has a bounded client count and adds polling latency;
it is not an IOCP throughput claim.

Each client has at most 32 queued frames and 256 KiB of queued wire data.
Oversized output or queue exhaustion closes the connection and reports send
failure. Handshake, incomplete input records, stalled writes and graceful drain
have five-second bounds. Idle established clients can keep a pending read.
Disconnect/stop cancels pending native operations and observes their completion
before releasing `OVERLAPPED` structures or buffers. Shutdown does not call
`FlushFileBuffers`, which can wait for a client to consume data.
[Microsoft completion semantics](https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-getoverlappedresult)

The shared communication layer now supports transport close/destroy operations
and sends RPC responses through the connection's write function. Pipe close
fails pending RPCs and frees the PT's owned devices/resources through the same
cleanup path used for WebSockets.

## C counter and tests

Build `windows-core-tests`, then run the counter against a configured Edge:

```powershell
.\build\windows-x64\bin\Debug\named-pipe-counter-pt.exe `
    --pipe '\\.\pipe\IzumaEdgeCorePT' --initial 5001
```

The C source is shared with the AF_UNIX counter target; the pipe build uses
Win32 pipe I/O and explicit record framing. It does not need Node or a PT SDK.
The client has a 16-KiB message limit and five-second I/O deadlines. It validates
the version reply, registers a unique PT/device and reports the gateway resource
path `/d/<device>/3300/0/5700`. Press Enter to increment after each fresh cloud
read and `q` to unregister/close. Automatic local operation is available with
`--auto --steps 2 --interval-ms 1000`. Counter resources are readable; this
example returns a method error to other server-originated PT operations.

`windows-core-named-pipe` runs the actual C counter against the production pipe
adapter and a JSON-RPC fixture. It exercises registration, counter encoding,
write-error propagation, reverse requests, split/coalesced records, invalid
length/version rejection, a 63-KiB record, concurrent clients, queue limits,
stalled-write/incomplete-frame deadlines, disconnects, pending-I/O shutdown,
duplicate ownership and pipe-name reclamation. Restricted-token checks exercise
an allowed client SID and a denied SID against the actual pipe; an access check
also verifies that the client grant excludes creating server instances.
`windows-core-runtime-config` checks TCP isolation settings, pipe validation
and the build capability. The AF_UNIX fixture also runs without a TCP listener.

```powershell
ctest --test-dir build/windows-x64 -C Debug --output-on-failure
ctest --test-dir build/windows-x64 -C Release --output-on-failure
```

Run the suite under the ordinary user token so its own restricted-token ACL
fixtures can operate. A restricted tool token may fail its pipe access check.
The console and fixture ACL checks do not qualify deployment as the actual
restricted Edge service. Actual LocalService/service-SID
allow/deny tests, cloud-originated writable/execute operations, longer soak/load,
remote rejection attempts and additional Windows versions need their own
qualification. Report real cloud reads separately from local RPC success.

## Qualification on October 3, 2026

Windows 10 Pro 22H2 x64, build 19045.6466; MSVC 19.44.35229.0; Windows SDK
26100; OpenSSL 3.5.9. With both IPC listeners compiled, BYOC Debug/Release
passed 11/11 tests and developer Debug/Release passed 9/9. With
`EDGE_WINDOWS_NAMED_PIPE=OFF`, BYOC Debug passed 10/10, including rejection of
enabled pipe configuration before cloud initialization. Restoring ON passed
the options, runtime configuration and named-pipe checks (3/3).

Temporary real developer Edge instances connected to the cloud in Debug and
Release with `tcpEnabled: false`. Both started while the CLI TCP address was
occupied; neither bound the configured TCP port. Native C pipe PTs registered
and received successful write acknowledgments for 5001 → 5002 → 5003 (Debug)
and 6001 → 6002 → 6003 (Release). An AF_UNIX C PT also registered, wrote
7001 → 7002 → 7003 and unregistered while the Release pipe PT remained
connected. This qualifies local IPC integration with a connected Edge, not
fresh cloud reads: the portal was signed out, so the named-pipe cloud read
milestone remains unverified. Earlier TCP/AF_UNIX cloud results are separate.

Private run logs, state, hashes and the qualification summary are retained under
the ignored `build/` tree. The installed `EdgeCore` service was not changed.
