/* SPDX-License-Identifier: Apache-2.0 */
#include <CoreFoundation/CoreFoundation.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/route.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <event2/event.h>
#include <event2/thread.h>
#include "edge_network_recovery.h"
#include "macos/edge_network_config.h"
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "line %d: %s\n", __LINE__, #x); exit(1); } } while (0)
static CFMutableDictionaryRef dictionary(void)
{ return CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks); }
static void configuration_tests(void)
{
    CFMutableDictionaryRef values = dictionary(), dns = dictionary(), ipv4 = dictionary();
    const void *servers[] = {CFSTR("192.0.2.1"), CFSTR("192.0.2.2")};
    CFArrayRef resolvers = CFArrayCreate(NULL, servers, 2, &kCFTypeArrayCallBacks);
    CFDictionarySetValue(dns, CFSTR("ServerAddresses"), resolvers);
    CFDictionarySetValue(dns, CFSTR("SupplementalMatchDomains"), CFSTR("corp.example"));
    CFDictionarySetValue(ipv4, CFSTR("InterfaceName"), CFSTR("utun4"));
    CFDictionarySetValue(values, CFSTR("State:/Network/Service/test-vpn/DNS"), dns);
    CFDictionarySetValue(values, CFSTR("State:/Network/Global/IPv4"), ipv4);
    CFDictionaryRef before = edge_macos_network_snapshot(values); CHECK(before);
    CFDictionarySetValue(ipv4, CFSTR("LeaseExpirationTime"), CFSTR("metadata-only"));
    CFDictionaryRef same = edge_macos_network_snapshot(values); CHECK(same && CFEqual(before, same));
    CFRelease(same);
    CFDictionarySetValue(dns, CFSTR("SupplementalMatchDomains"), CFSTR("other.example"));
    CFDictionaryRef scoped = edge_macos_network_snapshot(values); CHECK(scoped && !CFEqual(before, scoped));
    CFRelease(scoped);
    CFDictionarySetValue(dns, CFSTR("SupplementalMatchDomains"), CFSTR("corp.example"));
    const void *reversed[] = {servers[1], servers[0]};
    CFArrayRef order = CFArrayCreate(NULL, reversed, 2, &kCFTypeArrayCallBacks);
    CFDictionarySetValue(dns, CFSTR("ServerAddresses"), order);
    CFDictionaryRef reordered = edge_macos_network_snapshot(values); CHECK(reordered && !CFEqual(before, reordered));
    CFRelease(reordered); CFRelease(order);
    CFDictionarySetValue(dns, CFSTR("ServerAddresses"), resolvers);
    CFDictionarySetValue(ipv4, CFSTR("InterfaceName"), CFSTR("en0"));
    CFDictionaryRef path = edge_macos_network_snapshot(values); CHECK(path && !CFEqual(before, path));
    CFRelease(path);
    CFMutableDictionaryRef setup_dns = CFDictionaryCreateMutableCopy(NULL, 0, dns);
    CFDictionarySetValue(values, CFSTR("Setup:/Network/Service/test-vpn/DNS"), setup_dns);
    CFDictionaryRef setup = edge_macos_network_snapshot(values); CHECK(setup);
    CFDictionarySetValue(setup_dns, CFSTR("SearchDomains"), CFSTR("setup.example"));
    CFDictionaryRef setup_changed = edge_macos_network_snapshot(values);
    CHECK(setup_changed && !CFEqual(setup, setup_changed));
    CFRelease(setup_changed); CFRelease(setup);
    CFDictionaryRemoveValue(values, CFSTR("Setup:/Network/Service/test-vpn/DNS"));
    CFRelease(setup_dns);
    CFDictionaryRemoveAllValues(values);
    CFDictionaryRef empty = edge_macos_network_snapshot(values); CHECK(empty && !CFEqual(before, empty));
    CHECK(!edge_macos_network_snapshot(NULL));
    CFRelease(empty); CFRelease(before); CFRelease(resolvers);
    CFRelease(dns); CFRelease(ipv4); CFRelease(values);
}
static void route_tests(void)
{
    struct rt_msghdr route = {0};
    route.rtm_msglen = sizeof(route); route.rtm_version = RTM_VERSION;
    route.rtm_type = RTM_ADD; route.rtm_flags = RTF_UP | RTF_GATEWAY;
    CHECK(edge_macos_network_route_changes(&route, sizeof(route)) == EDGE_NETWORK_ROUTE);
    unsigned char unaligned[sizeof(route) + 1]; memcpy(unaligned + 1, &route, sizeof(route));
    CHECK(edge_macos_network_route_changes(unaligned + 1, sizeof(route)) == EDGE_NETWORK_ROUTE);
    route.rtm_type = RTM_CHANGE;
    CHECK(edge_macos_network_route_changes(&route, sizeof(route)) == EDGE_NETWORK_ROUTE);
    route.rtm_type = RTM_DELETE;
    CHECK(edge_macos_network_route_changes(&route, sizeof(route)) == EDGE_NETWORK_ROUTE);
    route.rtm_errno = EEXIST;
    CHECK(!edge_macos_network_route_changes(&route, sizeof(route)));
    route.rtm_errno = 0; route.rtm_flags |= RTF_LLINFO;
    CHECK(!edge_macos_network_route_changes(&route, sizeof(route)));
#ifdef RTF_WASCLONED
    route.rtm_flags = RTF_WASCLONED;
    CHECK(!edge_macos_network_route_changes(&route, sizeof(route)));
#endif
    route.rtm_type = RTM_GET; route.rtm_flags = RTF_UP;
    CHECK(!edge_macos_network_route_changes(&route, sizeof(route)));
    route.rtm_type = RTM_MISS;
    CHECK(!edge_macos_network_route_changes(&route, sizeof(route)));
    route.rtm_type = RTM_IFINFO;
    CHECK(edge_macos_network_route_changes(&route, sizeof(route)) == EDGE_MACOS_NETWORK_RECHECK);
    struct ifa_msghdr address = {0};
    address.ifam_msglen = sizeof(address); address.ifam_version = RTM_VERSION; address.ifam_type = RTM_NEWADDR;
    CHECK(edge_macos_network_route_changes(&address, sizeof(address)) == EDGE_NETWORK_ADDRESS);
    address.ifam_type = RTM_DELADDR;
    CHECK(edge_macos_network_route_changes(&address, sizeof(address)) == EDGE_NETWORK_ADDRESS);
    CHECK(edge_macos_network_route_changes(&route, 3) == EDGE_MACOS_NETWORK_RECHECK);
    route.rtm_msglen = 0;
    CHECK(edge_macos_network_route_changes(&route, sizeof(route)) == EDGE_MACOS_NETWORK_RECHECK);
    CHECK(edge_macos_network_route_changes(NULL, 1) == EDGE_MACOS_NETWORK_RECHECK);
    CHECK(!edge_macos_network_route_changes(NULL, 0));
}
static void unexpected(unsigned reason, void *context)
{ (void)reason; (void)context; CHECK(0); }
int main(void)
{
    configuration_tests(); route_tests();
    CHECK(!evthread_use_pthreads());
    struct event_base *base = event_base_new(); CHECK(base);
    for (int i = 0; i < 3; ++i) {
        struct edge_network_watch *watch = edge_network_watch_start(base, unexpected, NULL); CHECK(watch);
        CHECK(edge_network_watch_test_timer_pending(watch));
        edge_network_watch_cloud(watch, true, false);
        CHECK(!edge_network_watch_test_timer_pending(watch));
        edge_network_watch_cloud(watch, false, true);
        CHECK(edge_network_watch_test_timer_pending(watch));
        edge_network_watch_cloud(watch, true, false);
        CHECK(!edge_network_watch_test_timer_pending(watch));
        struct timeval delay = {0, 10000};
        CHECK(!event_base_loopexit(base, &delay));
        CHECK(!event_base_dispatch(base));
        edge_network_watch_stop(watch);
    }
    event_base_free(base);
    puts("macOS recovery: scoped DNS, resolver order, path snapshots, route framing/filtering and watcher lifecycle passed.");
    return 0;
}
