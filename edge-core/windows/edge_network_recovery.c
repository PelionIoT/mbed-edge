/* SPDX-License-Identifier: Apache-2.0 */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <powrprof.h>
#include <stdlib.h>
#include <stdio.h>
#include <wchar.h>
#include <event2/event.h>
#include "edge_network_recovery.h"
struct edge_network_watch {
    struct event *timer;
    HANDLE route, address, interface_change;
    HPOWERNOTIFY power;
    volatile LONG changes;
    edge_network_policy policy;
    uint64_t last_tick, dns_hash, last_dns_check;
    bool dns_valid;
    void (*reconnect)(unsigned, void *);
    void *context;
};
static VOID CALLBACK route_changed(PVOID context, PMIB_IPFORWARD_ROW2 row, MIB_NOTIFICATION_TYPE type)
{ (void)row; if (type != MibParameterNotification) InterlockedOr(&((struct edge_network_watch *)context)->changes, EDGE_NETWORK_ROUTE); }
static VOID CALLBACK address_changed(PVOID context, PMIB_UNICASTIPADDRESS_ROW row, MIB_NOTIFICATION_TYPE type)
{ (void)row; if (type != MibParameterNotification) InterlockedOr(&((struct edge_network_watch *)context)->changes, EDGE_NETWORK_ADDRESS); }
static VOID CALLBACK interface_changed(PVOID context, PMIB_IPINTERFACE_ROW row, MIB_NOTIFICATION_TYPE type)
{ (void)row; if (type != MibParameterNotification) InterlockedOr(&((struct edge_network_watch *)context)->changes, EDGE_NETWORK_ADDRESS); }
static ULONG CALLBACK power_changed(PVOID context, ULONG type, PVOID setting)
{
    (void)setting;
    if (type == PBT_APMRESUMEAUTOMATIC || type == PBT_APMRESUMESUSPEND)
        InterlockedOr(&((struct edge_network_watch *)context)->changes, EDGE_NETWORK_RESUME);
    return ERROR_SUCCESS;
}
static uint64_t hash_bytes(uint64_t hash, const void *bytes, size_t length)
{
    const unsigned char *data = bytes;
    while (length--) { hash ^= *data++; hash *= UINT64_C(1099511628211); }
    return hash;
}
/* Include DNS-only changes, which need not generate route/address notifications.
 * Do not hash structure padding, pointers, lifetimes or traffic counters. */
static bool dns_configuration(uint64_t *result)
{
    ULONG size = 16384, status;
    IP_ADAPTER_ADDRESSES *list = NULL;
    for (int attempt = 0; attempt < 3; ++attempt) {
        free(list); list = malloc(size);
        if (!list) return false;
        status = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST,
                                     NULL, list, &size);
        if (status != ERROR_BUFFER_OVERFLOW) break;
    }
    if (status != NO_ERROR && status != ERROR_NO_DATA) { free(list); return false; }
    uint64_t hash = 0;
    if (status == NO_ERROR) for (IP_ADAPTER_ADDRESSES *a = list; a; a = a->Next) {
        if (a->OperStatus != IfOperStatusUp || a->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;
        uint64_t member = hash_bytes(UINT64_C(14695981039346656037), &a->Luid.Value, sizeof(a->Luid.Value));
        member = hash_bytes(member, &a->Ipv4Metric, sizeof(a->Ipv4Metric));
        member = hash_bytes(member, &a->Ipv6Metric, sizeof(a->Ipv6Metric));
        if (a->DnsSuffix) member = hash_bytes(member, a->DnsSuffix, wcslen(a->DnsSuffix) * sizeof(wchar_t));
        for (IP_ADAPTER_DNS_SERVER_ADDRESS *d = a->FirstDnsServerAddress; d; d = d->Next) {
            const SOCKADDR *s = d->Address.lpSockaddr;
            if (!s) continue;
            member = hash_bytes(member, &s->sa_family, sizeof(s->sa_family));
            if (s->sa_family == AF_INET) member = hash_bytes(member, &((const SOCKADDR_IN *)s)->sin_addr, sizeof(IN_ADDR));
            else if (s->sa_family == AF_INET6) {
                const SOCKADDR_IN6 *v6 = (const SOCKADDR_IN6 *)s;
                member = hash_bytes(member, &v6->sin6_addr, sizeof(IN6_ADDR));
                member = hash_bytes(member, &v6->sin6_scope_id, sizeof(v6->sin6_scope_id));
            }
        }
        hash ^= member; /* Adapter enumeration order is immaterial. */
    }
    /* Route parameter notifications include routine lifetime refreshes. Hash
     * effective routing fields so those refreshes do not disrupt a healthy
     * connection, while metric/default/split-tunnel route changes do. */
    MIB_IPFORWARD_TABLE2 *routes = NULL;
    if (GetIpForwardTable2(AF_UNSPEC, &routes) != NO_ERROR) { free(list); return false; }
    for (ULONG i = 0; i < routes->NumEntries; ++i) {
        const MIB_IPFORWARD_ROW2 *r = &routes->Table[i];
        uint64_t member = hash_bytes(UINT64_C(14695981039346656037), &r->InterfaceLuid.Value, sizeof(r->InterfaceLuid.Value));
        member = hash_bytes(member, &r->Metric, sizeof(r->Metric));
        member = hash_bytes(member, &r->DestinationPrefix.PrefixLength, sizeof(r->DestinationPrefix.PrefixLength));
        if (r->DestinationPrefix.Prefix.si_family == AF_INET) {
            member = hash_bytes(member, &r->DestinationPrefix.Prefix.Ipv4.sin_addr, sizeof(IN_ADDR));
            member = hash_bytes(member, &r->NextHop.Ipv4.sin_addr, sizeof(IN_ADDR));
        } else if (r->DestinationPrefix.Prefix.si_family == AF_INET6) {
            member = hash_bytes(member, &r->DestinationPrefix.Prefix.Ipv6.sin6_addr, sizeof(IN6_ADDR));
            member = hash_bytes(member, &r->NextHop.Ipv6.sin6_addr, sizeof(IN6_ADDR));
        }
        hash ^= member;
    }
    FreeMibTable(routes);
    free(list); *result = hash; return true;
}
static void tick(evutil_socket_t descriptor, short events, void *context)
{
    (void)descriptor; (void)events;
    struct edge_network_watch *w = context;
    uint64_t now = GetTickCount64();
    unsigned changes = (unsigned)InterlockedExchange(&w->changes, 0);
    /* Also covers missed power notifications and console processes. */
    if (now - w->last_tick > 30000) changes |= EDGE_NETWORK_RESUME;
    w->last_tick = now;
    if (now - w->last_dns_check >= 5000) {
        uint64_t hash;
        if (dns_configuration(&hash)) {
            if (w->dns_valid && hash != w->dns_hash) changes |= EDGE_NETWORK_DNS;
            w->dns_hash = hash; w->dns_valid = true;
        }
        w->last_dns_check = now;
    }
    if (changes) edge_network_policy_change(&w->policy, now, changes);
    unsigned reason = edge_network_policy_step(&w->policy, now);
    if (reason) w->reconnect(reason, w->context);
}
struct edge_network_watch *edge_network_watch_start(struct event_base *base,
    void (*reconnect)(unsigned, void *), void *context)
{
    struct edge_network_watch *w = calloc(1, sizeof(*w));
    if (!w) return NULL;
    w->reconnect = reconnect; w->context = context;
    w->last_tick = GetTickCount64(); w->last_dns_check = w->last_tick;
    edge_network_policy_init(&w->policy, w->last_tick);
    w->dns_valid = dns_configuration(&w->dns_hash);
    DWORD route = NotifyRouteChange2(AF_UNSPEC, route_changed, w, FALSE, &w->route);
    DWORD address = NotifyUnicastIpAddressChange(AF_UNSPEC, address_changed, w, FALSE, &w->address);
    DWORD adapter = NotifyIpInterfaceChange(AF_UNSPEC, interface_changed, w, FALSE, &w->interface_change);
    DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS power = {power_changed, w};
    DWORD resume = PowerRegisterSuspendResumeNotification(DEVICE_NOTIFY_CALLBACK, &power, &w->power);
    fprintf(stderr, "Network recovery notifications: route=%lu address=%lu adapter=%lu power=%lu; DNS poll=5s.\n",
            route, address, adapter, resume);
    w->timer = event_new(base, -1, EV_PERSIST, tick, w);
    struct timeval interval = {1, 0};
    if (!w->timer || event_add(w->timer, &interval)) { edge_network_watch_stop(w); return NULL; }
    return w;
}
void edge_network_watch_cloud(struct edge_network_watch *w, bool connected, bool transient)
{ if (w) edge_network_policy_cloud(&w->policy, GetTickCount64(), connected, transient); }
void edge_network_watch_stop(struct edge_network_watch *w)
{
    if (!w) return;
    /* Notification callbacks only set atomic flags; cancellation runs on the
     * application thread, never inside a notification or while holding its lock. */
    if (w->route) CancelMibChangeNotify2(w->route);
    if (w->address) CancelMibChangeNotify2(w->address);
    if (w->interface_change) CancelMibChangeNotify2(w->interface_change);
    if (w->power) PowerUnregisterSuspendResumeNotification(w->power);
    if (w->timer) event_free(w->timer);
    free(w);
}
