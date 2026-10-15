# Local status and listener details

`GET /status` retains its existing fields and request/response behavior on Linux.
On Windows, status JSON is available through `\\.\pipe\IzumaEdgeCoreStatus`
by default. The Windows TCP `GET /status` listener remains available when
`"status": {"tcpEnabled": true}` is set in the runtime configuration; it is
disabled when the setting is omitted. Production builds add an optional `connectivity` object with
`schemaVersion: 1`. Consumers that only use `status`, device identity, version,
cloud server or error fields can continue to do so. The Windows monitor's
diagnostic parser accepts older responses without this object, but normal pipe
polling requires `connectivity.processId` to verify the service identity.

The extension contains `processId`, `uptimeSeconds`, `registeredPtCount`,
`registeredDeviceCount` and `listeners`. Uptime uses the existing monotonic Edge
clock. Counts and listener data are collected on the server event thread. No
cloud credentials, identity files, full configuration or client SID values are
included.

`registeredPtCount` counts registered protocol translators, excluding gateway
resource managers that share the internal registration list.

Each listener has `available`, `enabled`, `listening`, `address` and `protocol`.
`available` describes this platform/build, `enabled` describes startup selection,
and `listening` is set after successful listener initialization. Disabled
addresses may describe configuration and must not be displayed as active.

| Listener key | Linux | Windows | Address format |
| --- | --- | --- | --- |
| `http` | HTTP status server | Optional TCP status server, disabled by default | Bound numeric IP and port when listening; IPv6 is bracketed |
| `tcp` | Unavailable in the current Unix-socket server profile | Optional loopback PT WebSocket | `127.0.0.1:<port>` |
| `afUnix` | Existing PT Unix socket | Optional Winsock AF_UNIX WebSocket | Local socket path |
| `namedPipe` | Unavailable | Optional Win32 PT byte pipe | `\\.\pipe\<name>` |
| `statusPipe` | Unavailable | Default Win32 status pipe | `\\.\pipe\IzumaEdgeCoreStatus` |

## macOS Unix status

On Apple Silicon macOS 14+, `GET /status` uses a separate AF_UNIX HTTP socket.
The PT WebSocket socket keeps its existing `afUnix` entry. macOS adds
`connectivity.listeners.statusUnix`, with protocol `http` and an absolute local
socket path. TCP status is disabled by default; `--status-tcp` enables it with
`--bind 127.0.0.1` or `--bind ::1` and `--http-port`. Other bind addresses and
invalid ports are rejected. The `http` entry describes this optional TCP listener.

The foreground default is `edge-status/status.sock` beneath the working
directory. Use `--status-socket <path>` to select another path. Relative paths
resolve beneath the working directory; the absolute UTF-8 path must fit in 103
bytes plus its terminating NUL. Path components cannot be symlinks, `.` or `..`.
Use `/private/tmp` explicitly for temporary development paths because `/tmp` is
a system symlink. Installed deployments should use:

```text
/Library/Application Support/Izuma/EdgeCore/run/status/status.sock
```

Only the final status directory may be created by Core. It must be owned by
the running service UID, permit owner writes, and have no group write or world
permissions; `0750` or `0700` are suitable. Ancestors must belong to root or the
service UID and exclude group/world writes, apart from root-owned sticky
temporary directories. Extended ACL write grants are refused. These checks
also apply to the persistent lock file, which must be a regular owner-private
file with one link. Core holds an exclusive lock until shutdown and leaves the
lock file in place so future processes lock the same inode.

The socket has mode `0660` and inherits the protected status directory's group.
The installer selects that reader group, normally `staff`, and gives the
service permission to use it. Group readers require search access through the
parent path; they cannot replace the socket. Connecting requires socket write
permission even though the API is read-only. [Darwin's Unix socket access check](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/uipc_usrreq.c).

Startup refuses an active listener, regular file, symlink, or unexpected owner
at the socket path. A socket owned by the service is removed as stale only when
a nonblocking connection reports `ECONNREFUSED` and its inode still matches.
Shutdown removes only the socket inode created by this instance. The Unix
listener starts after local credential and PT initialization, so an
unprovisioned startup does not create a status socket.

Each macOS HTTP listener permits at most eight active connections. Connections
have a fixed five-second lifetime, including clients that keep sending partial
headers. Headers are limited to 8 KiB, request bodies to 1 KiB, and serialized
status JSON to 64 KiB. Responses close the connection and valid status replies
use `Cache-Control: no-store`. Oversized JSON returns HTTP 500 without a partial
snapshot. The Unix response uses the same URI redaction as the Windows pipe;
optional TCP retains the full URI as on Windows/Linux.

Native Debug/Release coverage includes real Unix HTTP requests, malformed and
oversized requests, slow clients, event-loop responsiveness, socket write
permission denial, ACL and symlink rejection, duplicate startup, stale/crashed
listener recovery, replacement-safe cleanup, URI redaction, kernel peer UID/PID,
and simultaneous optional TCP status. Cross-account/group access and the monitor's
launchd service-identity verification remain deployment qualification work.

## Linux and Windows listener details

The HTTP address is read from the bound socket, so an OS-selected port is
reported correctly. Windows reports `http.enabled: false` and
`http.listening: false` when the TCP status listener is disabled. PT TCP uses
the effective CLI/config address; `pt.tcpEnabled: false` keeps it non-listening
even if a CLI address is supplied. Linux retains
its existing Unix-socket listener, framing, configuration and cloud backend.
This change introduces no Win32 dependency into Linux sources.

The named-pipe entry also reports `maxClients`, `connectedClients`,
`allowedClientSidCount`, `remoteClientsAllowed` and `maxFrameBytes`. Connected
clients are established framing sessions, including sessions that have not yet
registered a PT; registered PT/device counts are separate. The SID count excludes
the server identity. Actual SID values and private deployment state are omitted.

The monitor's **Status** tab keeps the connection/service view and preferences.
Its **Details** tab shows current listeners, the cloud server, process/uptime,
PT/device counts and pipe usage/access. Cloud URI user information, path, query
and fragment are removed from its display and copied text. Details refresh with
each three-second poll. Failed/invalid polls clear current listener rows;
previous successful data is not shown as currently listening. Service state is
queried independently from SCM. On Windows, the monitor verifies that the
status pipe server and the JSON process ID match the running SCM service before
showing a connected state. It shows whether the optional TCP status endpoint is
listening and only enables its browser link when it is.

The status endpoint reports Edge's own cloud connection state. It does not
perform an independent cloud resource read or confirm a PT client's access
rights. The Windows pipe permits local interactive users to read status and
rejects remote clients. Enabling TCP status exposes the existing HTTP response
on the configured local address.
The pipe response limits `lwm2m-server-uri` to scheme and host/port, omitting
URI user information, path, query and fragment. The optional TCP endpoint
retains its existing response fields, including the full URI.

## Regression coverage

The shared C implementation has no Win32 dependency. HTTP address discovery
uses libevent's socket handle with Winsock on Windows and POSIX sockets on
Linux. Linux startup publishes its existing HTTP and AF_UNIX listeners, with
TCP and named pipes marked unavailable.

The existing Linux CppUTest suite includes listener snapshots, preservation of
the original status fields and a mixed PT/GRM registration count. Existing HTTP
status/error/request tests retain their original expectations. On a Linux test
host, run the repository's usual `make -f Makefile.test run-tests` command; the
new cases are included automatically in `edge-core-test`.

On October 4, 2026, Windows developer Debug/Release passed 10/10 tests each and
BYOC Debug/Release passed 12/12 each. Monitor Debug/Release passed both protocol
and native-tab tests, including Linux-shaped responses, older-core responses
and invalid optional metadata. Live Windows checks covered concurrent AF_UNIX
and named-pipe PTs with TCP disabled, runtime counts and cleanup, and the
effective TCP CLI address. A Linux build/runtime regression run is still pending
because the qualification host has no configured Linux runtime.

A further live TCP check registered a gateway resource manager and confirmed
that `registeredPtCount` stayed at zero. All temporary listeners and clients
were removed, while the installed EdgeCore service remained unchanged.

After the isolated tests, the installed restricted LocalService was upgraded
to unsigned qualification package 0.21.1007 on October 4. Cloud reconnection
with the same identity, private configuration preservation and unchanged
service startup/security settings passed. The native monitor also read the
installed service's metadata with ordinary user permissions. Its retained
selection listens on HTTP `127.0.0.1:8080` and TCP PT `127.0.0.1:7681`, with
compiled AF_UNIX and named pipes disabled. Previous package binaries remain
available for rollback.
