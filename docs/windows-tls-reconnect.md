# Windows TLS reconnect exhaustion

## Failure and fix

The Windows OpenSSL PAL allocated a new BIO type ID for every TLS context.
OpenSSL 3.x has only 127 such IDs per process. BIO_meth_free releases the method
but does not reclaim its type ID. After repeated reconnects, pal_tlsSetSocket
therefore fails permanently until Core restarts, even when the network is healthy.

The regression test reproduced PAL_ERR_TLS_RESOURCE (0xfff00001) on context 128.
The fix gives the per-context method the non-searchable BIO_TYPE_NONE plus
BIO_TYPE_SOURCE_SINK flags. The PAL never searches for its BIO by type.
Methods and BIOs retain their existing ownership and cleanup, and TLS never owns
or closes the application's PAL socket. The error log now includes the PAL status.

Reference: https://docs.openssl.org/3.5/man3/BIO_meth_new/

## Regression coverage

The Windows PAL suite creates and frees 1,024 TLS contexts, replaces their BIOs,
and confirms that the original PAL socket remains valid. Verified TLS, rejected
untrusted certificates and mutual certificate authentication run afterward in
the same process. Run the PAL suite in addition to the Core suite on both
Windows toolchains; the existing cross-platform workflow covers Core regressions.
An optional workflow change to add PAL checks is saved with the local evidence
because the configured GitHub OAuth token cannot update workflow files.

## Network recovery

This fix adds no network checks, timers, or discovery polling.
Windows route/address/interface notifications, DNS registry notifications and
suspend/resume callbacks remain the sources of network-change events.
The existing one-shot debounce and failed-connection retry deadlines are unchanged.
macOS continues to use its existing native network/power event sources.

## Laptop qualification

Upgrade the existing service/package without resetting or re-importing identity.
Back up the protected identity and compare provisioning/configuration hashes.
Validate the deployed executable hash, live cloud registration and device identity.
Record real adapter, DNS and route changes plus an actual suspend/resume, and
verify reconnects without restarting Core. Keep test evidence separate from
credential files, and restore every temporary network setting.
