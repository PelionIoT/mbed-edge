/* SPDX-License-Identifier: Apache-2.0 */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <powrprof.h>
#include <process.h>
#include <stdlib.h>
#include <stdio.h>
#include <wchar.h>
#include <event2/event.h>
#include <event2/thread.h>
#include "../edge_network_recovery.h"
#define NETWORK_RECHECK 32u
#define DNS_WATCHES 4
struct dns_registration { HKEY key; HANDLE event; const wchar_t *path; };
struct edge_network_watch {
    struct event *timer, *signal;
    HANDLE route, address, interface_change;
    HANDLE stop, worker;
    struct dns_registration dns[DNS_WATCHES];
    HPOWERNOTIFY power;
    volatile LONG changes;
    edge_network_policy policy;
    uint64_t dns_hash;
    bool dns_valid;
    void (*reconnect)(unsigned, void *);
    void *context;
};
static void notify(struct edge_network_watch *w, unsigned reason)
{
    InterlockedOr(&w->changes, (LONG)reason);
    event_active(w->signal, EV_TIMEOUT, 0);
}
static VOID CALLBACK route_changed(PVOID context, PMIB_IPFORWARD_ROW2 row, MIB_NOTIFICATION_TYPE type)
{ (void)row; notify(context, type == MibParameterNotification ? NETWORK_RECHECK : EDGE_NETWORK_ROUTE); }
static VOID CALLBACK address_changed(PVOID context, PMIB_UNICASTIPADDRESS_ROW row, MIB_NOTIFICATION_TYPE type)
{ (void)row; notify(context, type == MibParameterNotification ? NETWORK_RECHECK : EDGE_NETWORK_ADDRESS); }
static VOID CALLBACK interface_changed(PVOID context, PMIB_IPINTERFACE_ROW row, MIB_NOTIFICATION_TYPE type)
{ (void)row; notify(context, type == MibParameterNotification ? NETWORK_RECHECK : EDGE_NETWORK_ADDRESS); }
static ULONG CALLBACK power_changed(PVOID context, ULONG type, PVOID setting)
{
    (void)setting;
    if (type == PBT_APMRESUMEAUTOMATIC || type == PBT_APMRESUMESUSPEND)
        notify(context, EDGE_NETWORK_RESUME);
    return ERROR_SUCCESS;
}
static uint64_t hash_bytes(uint64_t hash, const void *bytes, size_t length)
{
    const unsigned char *data = bytes;
    while (length--) { hash ^= *data++; hash *= UINT64_C(1099511628211); }
    return hash;
}
/* Hash only DNS-policy subtrees, never the unrelated policy parent watched
 * when a DNS key does not exist yet. Enumeration order is immaterial. */
static bool policy_hash(HKEY parent, const wchar_t *path, unsigned depth, uint64_t *result)
{
    HKEY key;
    LSTATUS status = RegOpenKeyExW(parent, path, 0, KEY_READ, &key);
    if (status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND) { *result = 0; return true; }
    if (status != ERROR_SUCCESS || depth > 16) { if (status == ERROR_SUCCESS) RegCloseKey(key); return false; }
    DWORD children = 0, child_name = 0, values = 0, value_name = 0, value_data = 0;
    status = RegQueryInfoKeyW(key, NULL, NULL, NULL, &children, &child_name, NULL,
                             &values, &value_name, &value_data, NULL, NULL);
    DWORD capacity = child_name > value_name ? child_name : value_name;
    if (status || capacity > 32767 || value_data > 1024 * 1024) { RegCloseKey(key); return false; }
    wchar_t *name = calloc((size_t)capacity + 2, sizeof(wchar_t));
    unsigned char *data = malloc((size_t)value_data + 1);
    bool ok = name && data;
    uint64_t hash = 0;
    for (DWORD i = 0; ok && i < values; ++i) {
        DWORD length = capacity + 1, bytes = value_data, type = 0;
        status = RegEnumValueW(key, i, name, &length, NULL, &type, data, &bytes);
        if (status == ERROR_NO_MORE_ITEMS) break;
        if (status) { ok = false; break; }
        uint64_t member = hash_bytes(UINT64_C(14695981039346656037), name, length * sizeof(wchar_t));
        member = hash_bytes(member, &type, sizeof(type));
        hash ^= hash_bytes(member, data, bytes);
    }
    for (DWORD i = 0; ok && i < children; ++i) {
        DWORD length = capacity + 1;
        status = RegEnumKeyExW(key, i, name, &length, NULL, NULL, NULL, NULL);
        if (status == ERROR_NO_MORE_ITEMS) break;
        uint64_t child = 0;
        if (status || !policy_hash(key, name, depth + 1, &child)) { ok = false; break; }
        hash ^= hash_bytes(child, name, length * sizeof(wchar_t));
    }
    free(name); free(data); RegCloseKey(key); *result = hash;
    return ok;
}
static bool arm_dns(struct dns_registration *registration)
{
    if (registration->key) {
        LSTATUS status = RegNotifyChangeKeyValue(registration->key, TRUE,
            REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET | REG_NOTIFY_THREAD_AGNOSTIC,
            registration->event, TRUE);
        if (status == ERROR_SUCCESS) return true;
        RegCloseKey(registration->key); registration->key = NULL;
    }
    wchar_t path[512];
    wcscpy_s(path, 512, registration->path);
    /* Subscribe to the nearest existing ancestor so policy/key creation is
     * also an event. No registry keys are created or modified by Core. */
    while (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0, KEY_NOTIFY, &registration->key) != ERROR_SUCCESS) {
        wchar_t *separator = wcsrchr(path, L'\\');
        if (!separator) return false;
        *separator = 0;
    }
    return RegNotifyChangeKeyValue(registration->key, TRUE,
        REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET | REG_NOTIFY_THREAD_AGNOSTIC,
        registration->event, TRUE) == ERROR_SUCCESS;
}
static unsigned __stdcall dns_events(void *context)
{
    struct edge_network_watch *w = context;
    HANDLE handles[DNS_WATCHES + 1]; handles[0] = w->stop;
    for (unsigned i = 0; i < DNS_WATCHES; ++i) handles[i + 1] = w->dns[i].event;
    for (;;) {
        DWORD event = WaitForMultipleObjects(DNS_WATCHES + 1, handles, FALSE, INFINITE);
        if (event == WAIT_OBJECT_0 || event == WAIT_FAILED) break;
        unsigned i = event - WAIT_OBJECT_0 - 1;
        if (i >= DNS_WATCHES) break;
        /* Rearm before scheduling inspection; this thread otherwise sleeps
         * indefinitely and never scans network/DNS configuration on a timer. */
        if (!arm_dns(&w->dns[i])) {
            fprintf(stderr, "Network recovery: DNS registry notification could not be rearmed.\n");
            break;
        }
        notify(w, NETWORK_RECHECK);
    }
    return 0;
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
    const wchar_t *policies[] = {
        L"SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters",
        L"SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient"
    };
    for (unsigned i = 0; i < sizeof(policies) / sizeof(policies[0]); ++i) {
        uint64_t policy;
        if (!policy_hash(HKEY_LOCAL_MACHINE, policies[i], 0, &policy)) { free(list); return false; }
        hash ^= hash_bytes(policy, policies[i], wcslen(policies[i]) * sizeof(wchar_t));
    }
    free(list); *result = hash; return true;
}
static void schedule(struct edge_network_watch *w)
{
    event_del(w->timer);
    uint64_t deadline = edge_network_policy_deadline(&w->policy);
    if (deadline == UINT64_MAX) return;
    uint64_t now = GetTickCount64(), delay = deadline > now ? deadline - now : 0;
    struct timeval timeout = {(long)(delay / 1000), (long)((delay % 1000) * 1000)};
    event_add(w->timer, &timeout);
}
static void dispatch(evutil_socket_t descriptor, short events, void *context)
{
    (void)descriptor; (void)events;
    struct edge_network_watch *w = context;
    uint64_t now = GetTickCount64();
    unsigned changes = (unsigned)InterlockedExchange(&w->changes, 0);
    if (changes) {
        uint64_t hash;
        if (dns_configuration(&hash)) {
            if (w->dns_valid && hash != w->dns_hash) changes |= EDGE_NETWORK_DNS;
            w->dns_hash = hash; w->dns_valid = true;
        } else changes |= EDGE_NETWORK_DNS; /* A known OS event, with inspection unavailable. */
    }
    changes &= ~NETWORK_RECHECK;
    if (changes) edge_network_policy_change(&w->policy, now, changes);
    unsigned reason = edge_network_policy_step(&w->policy, now);
    if (reason) w->reconnect(reason, w->context);
    schedule(w);
}
struct edge_network_watch *edge_network_watch_start(struct event_base *base,
    void (*reconnect)(unsigned, void *), void *context)
{
    if (!base || !reconnect || evthread_make_base_notifiable(base)) return NULL;
    struct edge_network_watch *w = calloc(1, sizeof(*w));
    if (!w) return NULL;
    w->reconnect = reconnect; w->context = context;
    w->timer = evtimer_new(base, dispatch, w);
    w->signal = event_new(base, -1, 0, dispatch, w);
    w->stop = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!w->timer || !w->signal || !w->stop) { edge_network_watch_stop(w); return NULL; }
    edge_network_policy_init(&w->policy, GetTickCount64());
    w->dns_valid = dns_configuration(&w->dns_hash);
    DWORD route = NotifyRouteChange2(AF_UNSPEC, route_changed, w, FALSE, &w->route);
    DWORD address = NotifyUnicastIpAddressChange(AF_UNSPEC, address_changed, w, FALSE, &w->address);
    DWORD adapter = NotifyIpInterfaceChange(AF_UNSPEC, interface_changed, w, FALSE, &w->interface_change);
    DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS power = {power_changed, w};
    DWORD resume = PowerRegisterSuspendResumeNotification(DEVICE_NOTIFY_CALLBACK, &power, &w->power);
    fprintf(stderr, "Network recovery OS events: route=%lu address=%lu adapter=%lu power=%lu; no periodic polling.\n",
            route, address, adapter, resume);
    const wchar_t *paths[DNS_WATCHES] = {
        L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
        L"SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters",
        L"SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters",
        L"SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient"
    };
    for (unsigned i = 0; i < DNS_WATCHES; ++i) {
        w->dns[i].path = paths[i];
        w->dns[i].event = CreateEventW(NULL, FALSE, FALSE, NULL);
        if (!w->dns[i].event || !arm_dns(&w->dns[i])) { edge_network_watch_stop(w); return NULL; }
    }
    w->worker = (HANDLE)_beginthreadex(NULL, 0, dns_events, w, 0, NULL);
    if (!w->worker) { edge_network_watch_stop(w); return NULL; }
    fprintf(stderr, "Network recovery: DNS registry subscriptions=%u; worker waits for OS events.\n", DNS_WATCHES);
    schedule(w);
    return w;
}
void edge_network_watch_cloud(struct edge_network_watch *w, bool connected, bool transient)
{ if (w) { edge_network_policy_cloud(&w->policy, GetTickCount64(), connected, transient); schedule(w); } }
#ifdef EDGE_NETWORK_RECOVERY_TESTING
bool edge_network_watch_test_timer_pending(struct edge_network_watch *w)
{ return event_pending(w->timer, EV_TIMEOUT, NULL) != 0; }
#endif
void edge_network_watch_stop(struct edge_network_watch *w)
{
    if (!w) return;
    /* Notification callbacks only set atomic flags; cancellation runs on the
     * application thread, never inside a notification or while holding its lock. */
    if (w->route) CancelMibChangeNotify2(w->route);
    if (w->address) CancelMibChangeNotify2(w->address);
    if (w->interface_change) CancelMibChangeNotify2(w->interface_change);
    if (w->power) PowerUnregisterSuspendResumeNotification(w->power);
    if (w->stop) SetEvent(w->stop);
    if (w->worker) { WaitForSingleObject(w->worker, INFINITE); CloseHandle(w->worker); }
    for (unsigned i = 0; i < DNS_WATCHES; ++i) {
        if (w->dns[i].key) RegCloseKey(w->dns[i].key);
        if (w->dns[i].event) CloseHandle(w->dns[i].event);
    }
    if (w->stop) CloseHandle(w->stop);
    if (w->signal) event_free(w->signal);
    if (w->timer) event_free(w->timer);
    free(w);
}
