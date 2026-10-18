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

## Completed laptop qualification: 2026-10-18

Version 0.21.1039 was installed on the existing Windows laptop qualification
service. Core source was 7ea81c736d2c61f1d88d199e39324b8585b3bfeb, with
Cloud Client ec0a104 and monitor f2fc9bf (monitor version 0.1.2).
The service used automatic delayed startup and the deployed Core hash matched
the tested build. All 31 retained configuration/state files matched their
pre-install hashes before the updated service started.

The following checks used the same running Core PID and the original device
identity throughout; none restarted Core or reprovisioned it:

| Case | Result | Observed time to verified connectivity |
| --- | --- | --- |
| DNS connection-specific suffix changed | Passed; new authenticated cloud socket | 3.8 seconds |
| Original DNS suffix restored | Passed; new authenticated cloud socket | 9.4 seconds |
| Temporary split route added | Passed; new authenticated cloud socket | 8.8 seconds |
| Temporary split route removed | Passed; new authenticated cloud socket | 9.6 seconds |
| Wi-Fi disabled for 12 seconds, then enabled | Passed; new authenticated cloud socket | 17.6 seconds after re-enabling |
| Actual S3 suspend/resume, manually awakened on battery | Passed; Kernel-Power events 42/107 and new authenticated socket | 6.1 seconds after the suspend call returned |
| Settled idle observation | Passed; same authenticated socket for 30 seconds | No replacement during the interval |

The original provisioning CBOR hash still matched the protected backup after all
tests. DNS configuration and Wi-Fi state were restored, the test route was
removed, and all qualification helper processes exited. Core was connected at
completion. The collected post-upgrade log contained no new pal_tlsSetSocket
failures.

Test limitations and evidence: startup and recovery log notifications were not
reliable enough to drive the observer, so qualification used service-verified
local IPC status plus Windows TCP socket creation timestamps. Local status/table
observations were confined to the test harness; no production network discovery
polling was added. An early post-resume idle check saw one further socket refresh;
a fresh interval after settling passed. This is a functional qualification,
not a long-duration endurance run. Earlier failed observer attempts were retained
with the final evidence rather than overwritten.

Both Visual Studio 2022 and 2026 passed 16 Core and five PAL suites, including
the 1,024-context TLS regression and real verified/mutual TLS handshakes.
The Windows 10 build target remains 17763; this laptop run was on Windows 11.
Cross-platform CI passed all seven Windows, Linux, macOS 14 and macOS 26 jobs:
https://github.com/PelionIoT/mbed-edge/actions/runs/39059861107

Local detailed results:
D:/work/mbed-edge-windows-installer/build/tls-reconnect-laptop-20261017/result.json
