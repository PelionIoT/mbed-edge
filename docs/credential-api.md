# PT credential storage

The `credential_open` and `credential_request` JSON-RPC methods use the existing
PT connection and framing. Register the PT before opening a credential session.
Windows defaults to the local, ACL-restricted named pipe when that feature is
compiled in. AF_UNIX and IPv4 loopback WebSockets remain explicit alternatives.
Linux and macOS default to a Unix-domain WebSocket socket. To opt into IPv4
loopback use `--edge-pt-address 127.0.0.1:<port>`; remote addresses are rejected.
There is no automatic fallback between transports.

## Local enrollment

Before starting a listener, `--pt-credential-provision PATH` imports a private
JSON file into KCM. It is independent of cloud identity provisioning and can be
used on an already provisioned device. The file contains up to 16 namespaces:

```json
{"namespaces":[{"namespace":"sysmgmt","key":"<base64 of 32 random bytes>",
                 "items":["redfish.username","redfish.password","trust.state"]}]}
```

Use a distinct random key per namespace. Namespace and item identifiers contain
1–32 ASCII letters, digits, underscores, dots or hyphens, beginning with a letter.
Each namespace permits only its locally enrolled list of 1–32 distinct item
names. The namespace key grants access to that namespace; a registered PT name
alone grants no access. The API never accepts arbitrary KCM names or item types.

The configured primary and secondary PAL storage directories must also be
service-owned or root-owned private directories (0700 on Unix; only the service
user/dedicated service SID, SYSTEM and Administrators on Windows). Enrollment and credential operations
fail closed otherwise. Set the service umask to 0077 before first startup, and
protect the parent directories from replacement. Permission checks do not undo
any earlier exposure of a software root key.

On Unix the enrollment file must be a regular, single-link, non-symlink file,
owned by root or the effective service user and inaccessible to group/other
users (normally mode 0600). On Windows its owner and effective allow ACEs must
be limited to the current service user or its enabled dedicated service SID, SYSTEM and Administrators; reparse points
and hard links are rejected. The input is limited to 64 KiB. Enrollment is
create-only: identical canonical input is idempotent; changing an enrolled key
or allowlist is rejected. Multiple namespaces are enrolled independently.
Remove the enrollment startup option and the server's input copy after success.
Provision the appropriate namespace key to each authorized local client through
its private service configuration. Do not put it in cloud resources or command
arguments. Namespace-key rotation requires a separate local administrative
procedure; this API cannot replace its own authorization root.

KCM configuration items encrypt the namespace policy and values using the core's
configured secure-storage backend. Software SOTP still relies on host file
permissions and disk protection. This feature does not create hardware key
isolation or prevent restoring a complete older storage snapshot. It neither
exports nor shares the core's root key or TLS private keys.

Namespace policies and values are runtime KCM items. They survive ordinary
restarts. Core factory reset removes them; recovery requires local enrollment
and credential/trust provisioning again. It must not silently restore an older
rotated trust root from an installation default.

## Encrypted protocol, version 1

`credential_open` takes `{}` and returns:

```json
{"version":1,"challenge":"<base64 of 32 fresh random bytes>"}
```

The challenge belongs to the current PT connection. A new open invalidates its
previous challenge and resets the next sequence to zero. An already accepted
request can still finish. An open response contains no secret and is not proof
of server identity; clients authenticate the encrypted operation response.

`credential_request` takes exactly `namespace`, `sequence` and `envelope`.
Sequence is a nonnegative integer, starting at zero and incrementing exactly
once per accepted request, below 2^63−1. The core consumes it before queueing
work. Replays and out-of-order requests fail. On a timeout, cancellation or
protocol error, reopen instead of guessing the sequence or retrying a mutation.
Read back the revision to determine whether an uncertain mutation committed.

The envelope is canonical padded base64 of:

```
12-byte random nonce || AES-256-GCM ciphertext || 16-byte authentication tag
```

AES uses the locally provisioned 32-byte namespace key. Generate a new random
nonce for every request and response, including after reconnect. Associated data
is the following byte concatenation, without JSON serialization:

```
UTF-8 domain || 0x00 || ASCII namespace || 0x00 || 32-byte challenge || uint64_be sequence
```

The request domain is `edge-credential-v1:request`; the response domain is
`edge-credential-v1:response`. A response uses the same namespace, challenge and
sequence as its request. Both directions require authentication before parsing
or using plaintext. This prevents request/response reflection and binds messages
to their namespace and session. The envelope including nonce/tag is at most
6144 bytes. Encrypted values travel through PT, including loopback TCP; message
lengths and namespace names remain visible. There is no forward secrecy if the
namespace key is later compromised. Keep key usage below 2^32 envelopes and
provision a new namespace key before that limit.

The request plaintext is one of:

```json
{"op":"get","name":"redfish.password"}
{"op":"compare_exchange","name":"redfish.password","expected_revision":0,"value":"<base64 value>"}
{"op":"compare_exchange","name":"redfish.password","expected_revision":1,"value":null}
```

Values contain at most 4096 arbitrary bytes; an empty value is distinct from
`null` (deletion). A new item has revision zero and no value. Successful mutations
increment the revision; deleted items retain a revisioned tombstone. Reads return
`{"status":"ok","revision":N,"value":BASE64_OR_NULL}`. Successful mutations
return `{"status":"ok","revision":N}`; a stale expected revision returns
`{"status":"conflict","revision":CURRENT}` without changing the value.
An item outside the allowlist returns `{"status":"denied"}`. Results are JSON
plaintext inside a new encrypted response envelope: `{"envelope":"..."}`.

KCM work is serialized on a tasklet, independently of PT transport. There are
at most 32 queued credential operations. Each item uses two encrypted slots:
write the next revision to the older slot while retaining the current slot.
A failure does not intentionally delete the current revision. Corrupt/incomplete
slots fail closed instead of selecting a potentially stale value. Recovering
from storage corruption requires local administration. Tombstones provide
logical deletion; no forensic erasure guarantee is made for old slots, backups
or SSD media. Multiple-item transactions are not provided: keep trust keys,
rotation generation and replay state in one bounded record when atomicity is
required.

The methods retain the shared PT shutdown/service-availability checks and
standard `-32602` missing-request-ID error. Outer credential errors use `-32040` for authentication/session rejection and `-32043` for
storage, malformed encrypted operations or resource failure. Authentication
failures do not reveal whether a namespace exists. Error messages do not include
credentials. Clients must not log decrypted operations or responses.

The C wire helpers are declared in `pt-client-2/pt_credential_api.h`; they exchange
challenge/envelope buffers and leave authenticated encryption to the caller.
A complete Rust client and native-core qualification harness live in the
systems-management project. The API is local infrastructure: privileged cloud
operations and tenant trust rotation still require verification by their owning
application. Access to this store does not establish tenant authorization.
