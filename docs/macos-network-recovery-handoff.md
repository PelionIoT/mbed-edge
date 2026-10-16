# macOS network recovery handoff

## Status and branch

Continue on `codex/shared-network-recovery` in `PelionIoT/mbed-edge`.
The user requested code changes, this Markdown handoff, a new commit and a push;
the macOS agent will perform native compilation and runtime validation.

**Latest requirement: network/DNS discovery must be entirely OS-event driven
on both Windows and macOS.** The follow-up to `50bb40e` removes the periodic
watcher timers and snapshot scans from that earlier implementation. Fetch the
latest branch before continuing. One-shot event debounce and known connection
failure retries remain; a healthy watcher has no recovery timer armed when
there is no pending OS event. See [the four-project source comparison](network-change-open-source-review.md).

This branch integrates the existing macOS port (`4dd884af8746b63aaa26fa51aba1a5984074c2ba`)
with the Windows recovery prerequisite (`b9416983101c21b56e85398b6e4ccc75cd9bbbe7`).
The integration merge is `4d97778`. Check out the complete branch rather than
cherry-picking only its tip: the new change depends on both parents.
The published cloud-client/Darwin PAL revision remains
`b511cbd82d9674c2cf3595f3631d9f8951abdb0c`.

macOS native compilation and execution have **not** been performed on the
Windows authoring machine. Treat this as implementation ready for Mac validation,
not a qualified macOS release. No macOS installer, signing or notarization was
performed. The existing port targets Apple Silicon and macOS 14 or newer.

## Problem observed on Windows

After VPN changes and repeated laptop sleep/wake, the running Core reported
`ConnectNetworkError`, followed by repeated `ConnectDnsResolvingFailed` errors.
Retry intervals grew to roughly ten minutes. The hostname later resolved from
the host and the old service eventually recovered before the patch was applied.
This established a recovery-delay problem, not proof of a permanent resolver
failure. No provisioning material is included in this branch or handoff.

## Implementation

- `edge-core/edge_network_policy.c` and `edge_network_recovery.h`: shared policy
  moved out of `windows/`. Initial registration gets a 120-second deadline.
  Transient transport failures trigger retries starting at 15 seconds and
  increasing to a 120-second ceiling. New network/wake events reset backoff.
  Events settle for two seconds, with a ten-second storm bound and a ten-second
  minimum interval between forced recovery attempts. Successful registration
  disarms recovery. Non-transient errors suppress forced retries.
- `edge-core/macos/edge_network_recovery.c`: a dedicated CFRunLoop worker watches
  SystemConfiguration and IOKit. The Core libevent thread receives atomic reason
  flags and runs recovery. System callbacks never perform DNS queries, cloud
  registration or credential changes. IOKit sleep messages are acknowledged
  promptly; wake schedules recovery. `CFRunLoopRun` blocks for OS events, with
  custom run-loop sources for explicit configuration rechecks and shutdown.
  There is no heartbeat or clock-gap sleep detector. Required configuration
  and power subscription failures cause watcher initialization to fail.
- `edge-core/macos/edge_network_config.c`: normalized current-state snapshots
  include global/per-service DNS, scoped VPN DNS domains, resolver order,
  IPv4/IPv6 path fields and interface Link state. Lease timestamps and counters
  are excluded. Initial inspection and OS notifications are the only snapshot
  triggers. Both `State:` and `Setup:` per-service DNS keys are subscribed,
  including manual resolver changes; the latter was added after reviewing
  Firefox. Inspection failures preserve the old snapshot and subscription,
  request recovery for the known event and await a new OS notification.
- A nonblocking read-only `PF_ROUTE` socket watches route add/delete/change and
  address notifications, including split-tunnel changes. Neighbor/cache clones,
  failed route requests and `RTM_GET` replies are ignored. `RTM_IFINFO` causes a
  configuration recheck rather than reconnecting on traffic counters. Routing
  reads are bounded per event-loop turn. `RTM_MISS` is also ignored: failed
  lookups must not create a reconnect feedback loop. A failed socket can reopen
  on another OS event or a known connection-failure deadline; no reopen scan
  runs while the connection is healthy.
- Windows uses IP Helper route/address/interface callbacks, power callbacks and
  four DNS registry subscriptions. Its DNS worker uses
  `WaitForMultipleObjects(..., INFINITE)` and rearms each registry subscription
  before requesting inspection. Missing policy keys are watched through an
  existing ancestor. Both platforms wake libevent directly and schedule only
  the next policy deadline with a one-shot timer.
- `edge-client/edge_client.cpp` and `edge_client_impl.h`: native Windows/macOS
  recovery serializes with the cloud scheduler, pauses the old cloud connection,
  then resumes using the current platform resolver and routing configuration.
  The client object, translator objects and stored identity are reused.
- `edge-core/edge_server.c`: enables the watcher for Windows/macOS production
  builds, clears stale errors after successful registration, and logs recovery
  reason masks. Watchers stop before application event-base destruction.
- CMake selects one native watcher and links macOS CoreFoundation,
  SystemConfiguration and IOKit. Linux does not enable this watcher; its existing
  reconnect behavior is retained. The shared policy itself is portable C.

Reason mask: route=1, address=2, configuration/DNS=4, resume=8, fallback retry=16.
The internal configuration-recheck flag (32) is consumed before policy processing.
Connected still requires the cloud client's successful registration callback.

## Tests added and local checks

- `test/network-recovery`: standalone portable policy tests, including initial
  registration deadline, burst coalescing, sustained storms, bounded backoff,
  resume while backing off, permanent-error suppression and recovery thereafter.
  Deadline assertions verify that healthy/blocked states have no pending work.
- `test/macos-pal/macos_network_recovery_tests.c`: scoped DNS changes, resolver
  ordering, primary-interface changes, ignored lease metadata, empty snapshots,
  unaligned/truncated route frames, neighbor/failed-lookup filtering, `Setup:`
  DNS snapshots and repeated native watcher start/stop. Lifecycle assertions
  verify the timer is armed for startup/failure and disarmed after connection.
  These tests are wired into the full macOS test build.
- Portable policy tests: **1/1 passed** with MSVC 2026 on the Windows host.
- Windows native Core regression suite: **16/16 passed** with VS2026 and
  **16/16 passed** with VS2022 after the event-driven rewrite, including native
  registry subscription lifecycle and no-idle-timer assertions. Monitor/CLI
  regression checks passed **3/3** with each compiler. The unified 0.21.1035
  qualification MSI passed seven delivery checks and three branding checks.
  Commands used `build-windows.ps1 -Configuration Release -CoreTests -Jobs 4`,
  the matching generator, pinned OpenSSL SDK and workspace-local test temporary
  directory. The combined local log is in the sibling installer checkout at
  `build/logs/event-installer-0.21.1035.log` (ignored output, not pushed).
- The macOS-specific sources/tests have not been compiled or run here.
- Windows laptop: the event-driven 0.21.1035 qualification MSI installed with
  exit code 0, retained provisioning, matched the built executable hash and
  recovered from a controlled cloud TCP reset in 16.4 seconds in the same
  process (PID 28324). Subsequent live status was Connected. Startup logged
  successful route/address/interface/power and four DNS registry subscriptions.
  This is not a substitute for native DNS/VPN/wake event qualification.

## Continue on the Mac

Inspect the Mac checkout for local modifications first; preserve them rather
than resetting the checkout. Fetch and switch to the complete branch, then
initialize its pinned dependencies:

```sh
git fetch origin codex/shared-network-recovery
git switch --track origin/codex/shared-network-recovery
git submodule update --init --recursive
git status --short
git submodule status --recursive
```

If the local branch already exists, switch to it normally instead of creating
another tracking branch. Use a coherent Xcode/SDK pair as described in
`docs/macos-build.md`. Configure different variants sequentially in a checkout:
the inherited version-header generator writes into the source tree.

First run the policy tests independently:

```sh
cmake -S test/network-recovery -B build/recovery-policy -DCMAKE_BUILD_TYPE=Debug
cmake --build build/recovery-policy --parallel 3
ctest --test-dir build/recovery-policy --output-on-failure
```

Build the full native port using an existing verified OpenSSL SDK, or create
the pinned SDK in a new directory first:

```sh
# Run only when this output directory does not already contain a verified SDK.
bash macos/build-openssl.sh .build-cache/macos-openssl

bash build-macos.sh build/macos-recovery-debug \
  -DCMAKE_BUILD_TYPE=Debug \
  -DOPENSSL_ROOT_DIR="$PWD/.build-cache/macos-openssl/install"

bash build-macos.sh build/macos-recovery-release \
  -DCMAKE_BUILD_TYPE=Release \
  -DOPENSSL_ROOT_DIR="$PWD/.build-cache/macos-openssl/install"
```

The build script runs all native tests. To isolate the additions:

```sh
ctest --test-dir build/macos-recovery-debug \
  -R 'shared-network-recovery-policy|macos-core-network-recovery' \
  --output-on-failure
```

Run the new native lifecycle test under AddressSanitizer/UndefinedBehaviorSanitizer
and ThreadSanitizer in separate build trees when available. Review CF/IOKit
resource ownership, registration failures, cancellation before worker startup,
and shutdown during route/DNS callbacks. Check API availability/deprecation
warnings against the selected macOS 14+ SDK. Commit any required repairs on this
branch and update this validation record with actual outcomes.

## Required runtime qualification

Use a non-production retained identity in a private directory. Do not reset
storage or reprovision to make recovery pass. The existing
`macos/cloud-smoke.py` verifies initial connection and retained-identity startup,
but it does not automatically exercise VPN, route or sleep recovery.

1. Establish a real cloud connection and record Core's PID, cloud identity and
   status socket. Confirm native DNS and power notifications register, and
   check whether routing notifications work under the intended daemon account.
   Prove the worker remains blocked without periodic timer wakeups while healthy.
2. Toggle the target VPN on/off repeatedly, including its scoped DNS and
   split-tunnel modes; switch Wi-Fi/Ethernet; change DNS and restore it. Exercise
   DNS-only edits to `Setup:` as well as effective `State:` changes. Test a
   notification that precedes publication of the final resolver state.
3. Suspend/wake repeatedly, including wake with networking unavailable and
   restoring connectivity afterwards. Sleep must not gain a 30-second delay
   from missed IOKit acknowledgements.
4. Interrupt only Core's cloud connection and verify it reconnects in the same
   process. Exercise a prolonged outage to reach maximum backoff, then restore
   the network and verify a change/wake resets the backoff promptly.
5. Verify stable healthy operation does not reconnect on lease refreshes,
   neighbor activity or traffic counters. Verify an event flood does not starve
   translator traffic, status responses or shutdown.
6. Confirm translator registrations and device identity survive recovery, stale
   error status clears after registration, retries remain bounded, and no
   credential material is exposed in logs. Capture actual reconnection times.
7. Review subscription loss and route-socket failure behavior against the open
   source comparison's remaining gaps. Do not add a periodic scan fallback.

Do not label macOS recovery validated until these checks run on a real Mac.
The existing `.github/workflows/macos-checks.yml` covers macOS 14/26 Debug and
Release; the new tests are included through `test/macos-pal/CMakeLists.txt`.
Its push trigger does not include this handoff branch. CI can be dispatched on
the branch later; no native macOS CI run was requested for this handoff.

## References

- [Apple SCDynamicStore](https://developer.apple.com/documentation/systemconfiguration/scdynamicstore-gb2)
- [Apple sleep/wake notifications](https://developer.apple.com/library/archive/qa/qa1340/_index.html)
- [Apple routing socket manual source](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/man/man4/route.4)
