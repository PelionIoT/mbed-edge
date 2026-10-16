# Network change detection: comparison with four open source implementations

Reviewed: 2026-10-15. Scope: Windows and macOS network, route, DNS and wake
notifications relevant to Edge Core's recovery after VPN changes and sleep.

## Assessment

Keep native OS subscriptions, event-triggered state comparison, bounded event
coalescing and serialized connection recovery. These patterns appear across
Chromium, Firefox, Tailscale and Qt. A generic online/offline signal is
insufficient for our DNS-only and split-tunnel VPN requirements.

Our revised watcher follows that architecture without periodic network/DNS
inspection or clock-gap wake detection. The original five-second snapshot
fallback did **not** satisfy the user's requirement and has been removed on
both platforms. This comparison also identifies remaining coverage and
subscription-failure gaps; architectural similarity is not proof of equivalent
reliability or completed macOS qualification.

The most useful immediate change from this review was adding macOS
`Setup:/Network/Service/[^/]+/DNS` notifications alongside `State:` DNS
notifications, following Firefox's explicit coverage. A regression case also
confirms `RTM_MISS` cannot trigger recovery, a feedback-loop hazard documented
in Tailscale's route monitor. Both Mac tests await native execution.

## Method and reproducibility

I inspected upstream implementation files, rather than inferring behavior from
product descriptions. Each project was pinned to the revision below. Full
paths, immutable source URLs and SHA-256 hashes of the downloaded files are in
[the source manifest](network-change-open-source-sources.json). Downloaded
reference sources remain in ignored `build/network-review-sources/`; none of
their code was copied into Core.

| Independent project | Inspected revision | Reason for selection |
| --- | --- | --- |
| Chromium | `4d8446cfe178eafd3fa1b905af7e1d6fe9c6860e` | Separate network and DNS observers, large cross-platform networking stack |
| Firefox | `751f5671de2d327ff436154dfca6ed1733809163` | Direct comparison for IP Helper and SystemConfiguration notifications |
| Tailscale | `e9d5cdc3231edd3f93254c16f505fd86344a9faf` | VPN routing, notification noise and suspend/resume concerns |
| Qt | `ef648c80f7d8466425bd50ca453ccf934e7f34d5` | Modern Apple path monitoring and Windows connectivity subscriptions |

This is a source review, not a benchmark. I did not build these projects or
measure their reconnection latency. Statements about their behavior apply to
the inspected components/revisions, not every subsystem or product variant.
Recommendations below are engineering judgments drawn from that comparison.

## Case 1: Chromium

**Windows.** `NetworkChangeNotifierWin` receives `NotifyAddrChange` completion
through an event handle and rearms observation before announcing changes.
It applies distinct coalescing delays. Importantly, after an address event it
also queries connection type repeatedly at one-second intervals, with a bounded
poll count, because the OS's reported connectivity can lag. Notification
registration failures have a separate delayed retry path. Therefore this
component is event-initiated but is not an entirely polling-free model.
[Windows notifier source](https://github.com/chromium/chromium/blob/4d8446cfe178eafd3fa1b905af7e1d6fe9c6860e/net/base/network_change_notifier_win.cc).

DNS has its own watcher. It watches TCP/IP v4/v6, DNS Client and DNS policy
registry roots, plus the hosts file. Its registry callback rearms observation
before delivering the change; rearm failure is reported through the callback.
The source explicitly notes the limitation of optional policy keys that did
not exist when watching began.
[Windows DNS source](https://github.com/chromium/chromium/blob/4d8446cfe178eafd3fa1b905af7e1d6fe9c6860e/net/dns/dns_config_service_win.cc).

**macOS.** The Apple notifier includes `nw_path_monitor` support and
SystemConfiguration global interface/IPv4/IPv6 notifications. It compares
primary interfaces and relevant address lists before emitting IP changes.
This avoids treating every configuration callback as a meaningful change.
[Apple notifier source](https://github.com/chromium/chromium/blob/4d8446cfe178eafd3fa1b905af7e1d6fe9c6860e/net/base/network_change_notifier_apple.mm).

Its separate DNS watcher obtains the resolver configuration notification key
through dynamically loaded `dnsinfo` symbols, and consumes notifyd messages via
a readable file descriptor. A broken notification read cancels the watcher and
reports failure. That resolver-specific mechanism is deeper than Core's public
SystemConfiguration snapshots, but introduces an Apple SPI dependency that we
should not adopt casually.
[DNS watcher](https://github.com/chromium/chromium/blob/4d8446cfe178eafd3fa1b905af7e1d6fe9c6860e/net/dns/dns_config_watcher_mac.cc),
[notification descriptor](https://github.com/chromium/chromium/blob/4d8446cfe178eafd3fa1b905af7e1d6fe9c6860e/net/dns/notify_watcher_mac.cc).

**Comparison with Core.** Our separate Windows registry subscriptions and
rearm-before-inspection ordering match the relevant design. Watching an
existing ancestor covers later creation of optional policy keys. Core also
subscribes directly to route changes, needed for split tunnels. Retain those
choices; do not copy Chromium's connection-type polling. Improve our watcher
failure reporting and assess hosts-file coverage. On macOS, path monitoring
could complement our subscriptions, but cannot establish DNS-policy coverage
by itself.

## Case 2: Firefox

**Windows.** `nsNotifyAddrListener` registers `NotifyIpInterfaceChange` for
IPv4/IPv6. Its worker normally waits indefinitely on an event; a one-second
coalescing window temporarily supplies a finite wait. It enumerates adapters
and checksums relevant active-interface state because Windows emits changes
that should not all become application network changes. Shutdown signals the
worker and cancels the IP Helper registration.
[Windows source](https://github.com/mozilla-firefox/firefox/blob/751f5671de2d327ff436154dfca6ed1733809163/netwerk/system/win32/nsNotifyAddrListener.cpp).

**macOS.** `nsNetworkLinkService` combines reachability callbacks with
`SCDynamicStore` run-loop notifications. Its patterns explicitly include
per-service IPv4/IPv6, `State:` DNS and `Setup:` DNS. DNS callbacks dispatch a
resolver/suffix refresh through a 50 ms one-shot delay, acknowledging that
resolver state can trail notification delivery. It also has one-shot network-ID
work and special handling for EAPOL-related notifications.
[Mac source](https://github.com/mozilla-firefox/firefox/blob/751f5671de2d327ff436154dfca6ed1733809163/netwerk/system/mac/nsNetworkLinkService.mm).

**Comparison with Core.** This is the closest reference for an indefinitely
blocked worker plus event-driven coalescing. We use a two-second quiet period,
a ten-second storm bound and a ten-second minimum between forced reconnects;
those are Core policy choices, not values validated by Firefox. The `Setup:`
DNS subscription is now added to our Mac implementation. Firefox's delayed DNS
read exposes another qualification requirement: test delivery before final
resolver publication. If needed, inspect once after the event's debounce
deadline instead of introducing a periodic scan. Do not import the EAPOL
workaround without demonstrating that our different callback path needs it.

## Case 3: Tailscale

**Windows.** Its `netmon` backend uses WireGuard Windows address-change and
route-change callback wrappers. Callbacks hand work off promptly instead of
blocking the Windows callback thread. Startup/close state checks and callback
unregistration address lifetime and goroutine leaks. The backend also contains
a very long runtime bookkeeping ticker; it is not a frequent network scan.
[Windows source](https://github.com/tailscale/tailscale/blob/e9d5cdc3231edd3f93254c16f505fd86344a9faf/net/netmon/netmon_windows.go).

**macOS.** The backend blocks on an `AF_ROUTE` socket and parses routing
messages. It filters irrelevant interfaces and messages. In particular,
`RTM_MISS` is ignored because failed lookups scale with traffic and can cause
probe/change/probe feedback loops. It also excludes several interface names,
including `utun`, which is an application-specific choice.
[Darwin source](https://github.com/tailscale/tailscale/blob/e9d5cdc3231edd3f93254c16f505fd86344a9faf/net/netmon/netmon_darwin.go).

**Shared monitor.** Received OS messages request a state refresh, comparison
and callback delivery, with one-second event throttling. A function named
`Poll()` is called from the event pump; its name alone does not prove periodic
polling. However, the same component separately runs a real 15-second wall-time
timer on Windows and macOS to infer sleep from time jumps. Receive failures
also use delayed retries. These distinctions matter for our requirement.
[Shared monitor source](https://github.com/tailscale/tailscale/blob/e9d5cdc3231edd3f93254c16f505fd86344a9faf/net/netmon/netmon.go).

**Comparison with Core.** Keep route sockets, short callbacks, state comparison,
message validation and explicit teardown. Core already ignores route misses,
neighbors and cloned-cache routes; the new test makes the miss case explicit.
Do not copy the `utun` exclusion: other VPN interfaces are central to our
requirements. Do not copy the periodic wall-clock detector; Core uses Windows
power callbacks and IOKit sleep/wake callbacks. The inspected `netmon` files
alone are not evidence of complete Tailscale DNS-change coverage.

## Case 4: Qt Network Information

**Windows.** Qt subscribes to `INetworkListManagerEvents` through a COM
connection point. When built with C++/WinRT support it additionally subscribes
to `NetworkInformation::NetworkStatusChanged` for transport/cost information.
It subscribes before obtaining initial connectivity, reports subscription
failures, and unregisters on shutdown. Connectivity callbacks feed Qt signals.
[Windows subscription source](https://github.com/qt/qtbase/blob/ef648c80f7d8466425bd50ca453ccf934e7f34d5/src/plugins/networkinformation/networklistmanager/qnetworklistmanagerevents.cpp).

**macOS.** Qt creates an `nw_path_monitor`, supplies update/cancel handlers and
a serial dispatch queue, and derives reachability and transport from delivered
paths. Callback state is protected through cancellation, with final deletion
in the cancel handler. The inspected Apple backend does not schedule a
periodic discovery timer.
[Apple source](https://github.com/qt/qtbase/blob/ef648c80f7d8466425bd50ca453ccf934e7f34d5/src/plugins/networkinformation/apple/qapplenetworkinformationbackend.mm).

Qt's public documentation cautions that reported reachability is not a reliable
precondition for attempting a connection; Windows's notion of online status
can depend on access to Microsoft's server.
[Qt documentation](https://doc.qt.io/qt-6/qnetworkinformation.html#reachability-prop).

**Comparison with Core.** `nw_path_monitor` is a credible modern event-driven
addition for macOS if native tests expose path-change gaps. Qt's inspected
backend exposes reachability/transport, not individual resolver lists or route
destinations. Replacing our DNS and route observers with that abstraction would
lose information we need. Keep cloud registration as the authority for
Connected status. Adopt the subscribe-before-initial-read ordering and verify
that queued callbacks cannot outlive watcher shutdown.

## Comparison matrix

| Concern | Observed upstream pattern | Current Core method | Assessment |
| --- | --- | --- | --- |
| Address/interface changes | Windows IP Helper; Apple SystemConfiguration/path callbacks | IP Helper on Windows; SystemConfiguration plus routing socket on Mac | Sound native event sources |
| DNS-only changes | Dedicated Chromium DNS observers; Firefox `State:` and `Setup:` DNS | Windows registry subscriptions; Mac global/service DNS including `Setup:` | Better than reachability alone; coverage gaps below remain |
| VPN route changes | Tailscale route callbacks and routing socket | `NotifyRouteChange2` and `PF_ROUTE`; no blanket VPN-interface exclusion | Appropriate for split tunnels |
| Notification noise | Checksums/snapshot comparison and coalescing | Stable fields, atomic reason flags, bounded debounce | Similar pattern; latency must be measured |
| Wake detection | Tailscale periodic clock checks; native power APIs are available | Windows power callbacks and Mac IOKit | Meets event-only constraint |
| Healthy-idle discovery | Mixed: Qt callback-only; Tailscale periodic clock timer | Infinite OS wait / blocked CFRunLoop; no periodic recovery timer | Required Core behavior, covered by timer-state assertions |
| Broken subscription | Error callbacks, failed start and/or delayed re-registration | Mixed fail-start, logged degradation and conditional re-open | Needs stronger consistency and fault tests |
| Actual destination health | Reachability abstractions do not prove service availability | Cloud registration callback determines Connected | Keep this distinction |

## Remaining gaps and decisions

These are findings in the current Core implementation, not claims that an
upstream project guarantees every event is delivered.

1. **Subscription failures need explicit health and recovery.** Windows logs
   IP Helper/power registration errors but can return a watcher with incomplete
   subscriptions. If DNS registry rearming fails, the DNS worker logs and exits;
   it does not currently notify Core that DNS observation stopped. Mac requires
   configuration/power sources but tolerates an unavailable route socket. Add
   consistent degraded-state reporting and fault tests. Re-establish a broken
   subscription from a known-failure action or another OS event; never replace
   it with a periodic healthy-state scan.

2. **Notification time and usable configuration time can differ.** Core's
   Windows snapshot comparison and Mac configuration snapshot currently happen
   promptly after notification; the connection operation is debounced later.
   An early snapshot could look unchanged and suppress the only notification.
   Test delayed publication explicitly. A single state read scheduled by that
   notification after settling is compatible with event-driven discovery;
   repeated timed reads to hunt for a change are not the chosen design.

3. **Windows global DNS settings need broader semantic comparison.** Registry
   observation includes TCP/IP roots, but the current fingerprint concentrates
   on active adapters' DNS/suffix/metrics, route fields and DNS policy subtrees.
   It does not explicitly hash all global TCP/IP search-list/devolution values.
   A notification with no change in the selected fields can be filtered out.
   Add selected global resolver fields and DNS-only tests before claiming
   exhaustive DNS-configuration coverage. Avoid hashing lease timestamps or
   entire unrelated registry trees.

4. **Hosts-file edits are outside this watcher's coverage.** Chromium observes
   the Windows hosts file separately; Core currently does not on either OS.
   Add native directory/file change events if local hostname overrides belong
   in the supported recovery contract. Keep this distinct from adapter DNS.

5. **Public macOS subscriptions need real VPN qualification.** `State:` and
   `Setup:` snapshots cover selected public DNS/path properties; this is not
   proof of equivalence to Chromium's resolver-specific notification channel.
   Test scoped DNS, resolver order, Network Extension VPNs, split routes,
   wake and notification-service interruption on a Mac. Consider a public
   `nw_path_monitor` as a complementary signal based on that evidence.

6. **Avoid unnecessary healthy reconnects.** Core currently treats substantive
   route add/delete events broadly, even when unrelated to the cloud endpoint.
   Debounce limits the rate but does not prove endpoint relevance. Measure
   VPN/VM route churn before adding complexity such as destination-specific
   route comparisons. Continue to reject neighbor/counter/lookup-miss noise.

7. **An OS configuration event is not promised for every remote outage.** A
   resolver service or upstream route may fail and recover without a local
   address, route or configuration change. Keep socket/client error handling
   and bounded one-shot retries after a known connection failure. Those retries
   retry the failed operation; they do not inspect the network periodically.

## Core validation and release boundary

- Portable policy suite: **1/1 passed** on Windows/MSVC 2026, including explicit
  next-deadline and no-work-when-healthy assertions.
- Event-driven Windows Core suite: **16/16 passed** with VS2022 and **16/16
  passed** with VS2026. Monitor/CLI checks: **3/3** with each toolchain.
- One unified qualification MSI, version **0.21.1035**, passed **7** delivery
  checks and **3** branding checks. Its Windows 10 build 17763 target remains;
  this does not substitute for running it on Windows 10.
- The event-driven **0.21.1035** qualification build is installed on the laptop.
  MSI returned **0**, the running executable hash matched the built payload,
  and retained provisioning hashes were unchanged. It recovered from a
  controlled reset of its cloud TCP connection in **16.4 seconds**, in the same
  service process (**28324**); live status was subsequently **Connected**.
  Service startup logs confirmed all four IP Helper/power registrations
  succeeded and four DNS registry subscriptions were active. Local evidence is
  in the installer checkout's ignored `build/event-retest-20261015/` directory.
  This validates known-failure recovery, not every OS notification path.
- Mac sources, including the new `Setup:` and route-miss assertions, have
  **not** been compiled or run on this Windows host. The
  [Mac handoff](macos-network-recovery-handoff.md) lists native checks.

Before a production release, test real DNS-only changes, VPN route changes,
sleep/wake, notification loss, event storms and shutdown during callbacks.
Demonstrate no periodic watcher wakeups while healthy. A unit timer assertion
and a TCP reset are useful evidence but do not qualify the whole OS event
delivery path. The practical recommendation is to keep this event-driven
architecture and close the named gaps through targeted implementation and
native qualification.
