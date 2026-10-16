/* SPDX-License-Identifier: Apache-2.0 */
#include <CoreFoundation/CoreFoundation.h>
#include <SystemConfiguration/SystemConfiguration.h>
#include <IOKit/IOMessage.h>
#include <IOKit/pwr_mgt/IOPMLib.h>
#include <mach/mach_time.h>
#include <sys/socket.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <event2/event.h>
#include <event2/thread.h>
#include <event2/util.h>
#include "../edge_network_recovery.h"
#include "edge_network_config.h"

struct edge_network_watch {
    struct event *timer, *signal, *route_event;
    int route_fd, route_error;
    mach_timebase_info_data_t timebase;
    atomic_uint changes;
    atomic_bool stopping;
    pthread_t worker;
    pthread_mutex_t lock;
    pthread_cond_t ready;
    bool thread_started, worker_ready, worker_failed;
    CFRunLoopRef run_loop;
    CFRunLoopSourceRef config_source, stop_source;
    edge_network_policy policy;
    void (*reconnect)(unsigned, void *);
    void *context;
};
struct configuration_worker {
    struct edge_network_watch *watch;
    SCDynamicStoreRef store;
    CFRunLoopSourceRef store_source, power_source;
    CFArrayRef keys, patterns;
    CFDictionaryRef previous;
    io_connect_t power_connection;
    io_object_t power_notifier;
    IONotificationPortRef power_port;
    bool inspection_failed;
};
static uint64_t now_ms(struct edge_network_watch *w)
{
    return (uint64_t)((long double)mach_continuous_time() * w->timebase.numer /
                      w->timebase.denom / 1000000.0L);
}
static void changed(struct edge_network_watch *w, unsigned reason)
{
    atomic_fetch_or_explicit(&w->changes, reason, memory_order_relaxed);
    event_active(w->signal, EV_TIMEOUT, 0);
}
/* Runs only at initialization or in response to an OS notification. The CF
 * worker never wakes on a timer and never performs a DNS query/network probe. */
static void inspect_configuration(void *context)
{
    struct configuration_worker *worker = context;
    CFDictionaryRef raw = SCDynamicStoreCopyMultiple(worker->store, worker->keys, worker->patterns);
    CFDictionaryRef snapshot = raw ? edge_macos_network_snapshot(raw) : NULL;
    if (raw) CFRelease(raw);
    if (!snapshot) {
        if (!worker->inspection_failed)
            fprintf(stderr, "Network recovery: OS notification received but configuration inspection failed (SCError=%d).\n", SCError());
        worker->inspection_failed = true;
        changed(worker->watch, EDGE_NETWORK_DNS);
        return; /* Preserve the previous snapshot and the OS subscription. */
    }
    if (worker->inspection_failed) fprintf(stderr, "Network recovery: configuration inspection restored.\n");
    worker->inspection_failed = false;
    if (worker->previous && !CFEqual(worker->previous, snapshot)) changed(worker->watch, EDGE_NETWORK_DNS);
    if (worker->previous) CFRelease(worker->previous);
    worker->previous = snapshot;
}
static void store_changed(SCDynamicStoreRef store, CFArrayRef keys, void *context)
{ (void)store; (void)keys; inspect_configuration(context); }
static void stop_requested(void *context)
{ CFRunLoopStop(((struct edge_network_watch *)context)->run_loop); }
static void power_changed(void *context, io_service_t service, natural_t type, void *argument)
{
    (void)service;
    struct configuration_worker *worker = context;
    if (type == kIOMessageCanSystemSleep || type == kIOMessageSystemWillSleep)
        IOAllowPowerChange(worker->power_connection, (long)(intptr_t)argument);
    else if (type == kIOMessageSystemHasPoweredOn) {
        inspect_configuration(worker);
        changed(worker->watch, EDGE_NETWORK_RESUME);
    }
}
static void *configuration_thread(void *context)
{
    struct edge_network_watch *w = context;
    struct configuration_worker worker = {0}; worker.watch = w;
    const void *keys[] = {CFSTR("State:/Network/Global/IPv4"), CFSTR("State:/Network/Global/IPv6"), CFSTR("State:/Network/Global/DNS")};
    const void *patterns[] = {
        CFSTR("State:/Network/Service/[^/]+/(IPv4|IPv6|DNS)"),
        CFSTR("Setup:/Network/Service/[^/]+/DNS"),
        CFSTR("State:/Network/Interface/[^/]+/(Link|IPv4|IPv6)")
    };
    worker.keys = CFArrayCreate(NULL, keys, sizeof(keys) / sizeof(keys[0]), &kCFTypeArrayCallBacks);
    worker.patterns = CFArrayCreate(NULL, patterns, sizeof(patterns) / sizeof(patterns[0]), &kCFTypeArrayCallBacks);
    CFRunLoopRef loop = CFRunLoopGetCurrent();
    w->run_loop = (CFRunLoopRef)CFRetain(loop);
    CFRunLoopSourceContext config_context = {0};
    config_context.info = &worker; config_context.perform = inspect_configuration;
    w->config_source = CFRunLoopSourceCreate(NULL, 0, &config_context);
    CFRunLoopSourceContext stop_context = {0};
    stop_context.info = w; stop_context.perform = stop_requested;
    w->stop_source = CFRunLoopSourceCreate(NULL, 0, &stop_context);
    SCDynamicStoreContext sc_context = {0, &worker, NULL, NULL, NULL};
    worker.store = SCDynamicStoreCreate(NULL, CFSTR("com.izuma.edge.network-recovery"), store_changed, &sc_context);
    if (worker.store && SCDynamicStoreSetNotificationKeys(worker.store, worker.keys, worker.patterns))
        worker.store_source = SCDynamicStoreCreateRunLoopSource(NULL, worker.store, 0);
    worker.power_connection = IORegisterForSystemPower(&worker, &worker.power_port, power_changed, &worker.power_notifier);
    if (worker.power_connection && worker.power_port)
        worker.power_source = IONotificationPortGetRunLoopSource(worker.power_port);
    bool failed = !w->config_source || !w->stop_source || !worker.store_source || !worker.power_source;
    if (!failed) {
        CFRunLoopAddSource(loop, w->config_source, kCFRunLoopDefaultMode);
        CFRunLoopAddSource(loop, w->stop_source, kCFRunLoopDefaultMode);
        CFRunLoopAddSource(loop, worker.store_source, kCFRunLoopDefaultMode);
        CFRunLoopAddSource(loop, worker.power_source, kCFRunLoopDefaultMode);
        inspect_configuration(&worker);
    }
    fprintf(stderr, "Network recovery: macOS DNS=%s power=%s; OS events only, no periodic polling.\n",
            worker.store_source ? "notifications" : "unavailable", worker.power_source ? "notifications" : "unavailable");
    pthread_mutex_lock(&w->lock);
    w->worker_failed = failed; w->worker_ready = true;
    pthread_cond_signal(&w->ready); pthread_mutex_unlock(&w->lock);
    /* The persistent stop source handles stop-before-run without a heartbeat. */
    while (!failed && !atomic_load_explicit(&w->stopping, memory_order_acquire)) CFRunLoopRun();
    if (worker.power_notifier) IODeregisterForSystemPower(&worker.power_notifier);
    if (worker.power_source) CFRunLoopRemoveSource(loop, worker.power_source, kCFRunLoopDefaultMode);
    if (worker.power_port) IONotificationPortDestroy(worker.power_port);
    if (worker.power_connection) IOServiceClose(worker.power_connection);
    if (worker.store_source) {
        CFRunLoopRemoveSource(loop, worker.store_source, kCFRunLoopDefaultMode);
        CFRelease(worker.store_source);
    }
    if (w->config_source) CFRunLoopRemoveSource(loop, w->config_source, kCFRunLoopDefaultMode);
    if (w->stop_source) CFRunLoopRemoveSource(loop, w->stop_source, kCFRunLoopDefaultMode);
    if (worker.store) CFRelease(worker.store);
    if (worker.previous) CFRelease(worker.previous);
    CFRelease(worker.keys); CFRelease(worker.patterns);
    return NULL;
}
static void open_route_watch(struct edge_network_watch *w);
static void schedule(struct edge_network_watch *w)
{
    event_del(w->timer);
    uint64_t deadline = edge_network_policy_deadline(&w->policy);
    if (deadline == UINT64_MAX) return;
    uint64_t now = now_ms(w), delay = deadline > now ? deadline - now : 0;
    struct timeval timeout = {(long)(delay / 1000), (int)((delay % 1000) * 1000)};
    event_add(w->timer, &timeout);
}
static void dispatch(evutil_socket_t descriptor, short events, void *context)
{
    (void)descriptor; (void)events;
    struct edge_network_watch *w = context;
    uint64_t now = now_ms(w);
    unsigned reasons = atomic_exchange_explicit(&w->changes, 0, memory_order_relaxed);
    if (w->route_fd < 0) open_route_watch(w); /* An OS event or known failure, never a scan timer. */
    if (reasons) edge_network_policy_change(&w->policy, now, reasons);
    unsigned reason = edge_network_policy_step(&w->policy, now);
    if (reason) w->reconnect(reason, w->context);
    schedule(w);
}
static void route_read(evutil_socket_t descriptor, short events, void *context)
{
    (void)events;
    struct edge_network_watch *w = context;
    unsigned changes = 0;
    for (unsigned batch = 0; batch < 32; ++batch) {
        unsigned char buffer[16384];
        ssize_t count = recv((int)descriptor, buffer, sizeof(buffer), 0);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
        if (count <= 0) {
            event_del(w->route_event); close(w->route_fd); w->route_fd = -1;
            changes |= EDGE_MACOS_NETWORK_RECHECK;
            break;
        }
        changes |= edge_macos_network_route_changes(buffer, (size_t)count);
    }
    if (changes & EDGE_MACOS_NETWORK_RECHECK) {
        CFRunLoopSourceSignal(w->config_source); CFRunLoopWakeUp(w->run_loop);
    }
    changed(w, changes & ~EDGE_MACOS_NETWORK_RECHECK);
}
static void open_route_watch(struct edge_network_watch *w)
{
    if (w->route_event) { event_free(w->route_event); w->route_event = NULL; }
    w->route_fd = socket(PF_ROUTE, SOCK_RAW, AF_UNSPEC);
    int error = w->route_fd < 0 ? errno : 0;
    if (!error && (evutil_make_socket_nonblocking(w->route_fd) || evutil_make_socket_closeonexec(w->route_fd))) error = errno;
    if (!error) {
        int size = 256 * 1024;
        (void)setsockopt(w->route_fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
        w->route_event = event_new(event_get_base(w->timer), w->route_fd, EV_READ | EV_PERSIST, route_read, w);
        if (!w->route_event || event_add(w->route_event, NULL)) error = ENOMEM;
    }
    if (error) {
        if (error != w->route_error) fprintf(stderr, "Network recovery: routing notifications unavailable (errno=%d).\n", error);
        if (w->route_event) { event_free(w->route_event); w->route_event = NULL; }
        if (w->route_fd >= 0) close(w->route_fd);
        w->route_fd = -1;
    } else fprintf(stderr, "Network recovery: routing notifications %s.\n", w->route_error ? "restored" : "enabled");
    w->route_error = error;
}
struct edge_network_watch *edge_network_watch_start(struct event_base *base,
    void (*reconnect)(unsigned, void *), void *context)
{
    if (!base || !reconnect || evthread_make_base_notifiable(base)) return NULL;
    struct edge_network_watch *w = calloc(1, sizeof(*w));
    if (!w) return NULL;
    w->route_fd = -1; w->reconnect = reconnect; w->context = context;
    atomic_init(&w->changes, 0); atomic_init(&w->stopping, false);
    if (mach_timebase_info(&w->timebase) != KERN_SUCCESS || !w->timebase.denom) { free(w); return NULL; }
    if (pthread_mutex_init(&w->lock, NULL)) { free(w); return NULL; }
    if (pthread_cond_init(&w->ready, NULL)) { pthread_mutex_destroy(&w->lock); free(w); return NULL; }
    edge_network_policy_init(&w->policy, now_ms(w));
    w->timer = evtimer_new(base, dispatch, w);
    w->signal = event_new(base, -1, 0, dispatch, w);
    if (!w->timer || !w->signal) { edge_network_watch_stop(w); return NULL; }
    if (pthread_create(&w->worker, NULL, configuration_thread, w)) { edge_network_watch_stop(w); return NULL; }
    w->thread_started = true;
    pthread_mutex_lock(&w->lock);
    while (!w->worker_ready) pthread_cond_wait(&w->ready, &w->lock);
    pthread_mutex_unlock(&w->lock);
    if (w->worker_failed) { edge_network_watch_stop(w); return NULL; }
    open_route_watch(w); schedule(w);
    return w;
}
void edge_network_watch_cloud(struct edge_network_watch *w, bool connected, bool transient)
{ if (w) { edge_network_policy_cloud(&w->policy, now_ms(w), connected, transient); schedule(w); } }
#ifdef EDGE_NETWORK_RECOVERY_TESTING
bool edge_network_watch_test_timer_pending(struct edge_network_watch *w)
{ return event_pending(w->timer, EV_TIMEOUT, NULL) != 0; }
#endif
void edge_network_watch_stop(struct edge_network_watch *w)
{
    if (!w) return;
    if (w->route_event) event_free(w->route_event);
    if (w->route_fd >= 0) close(w->route_fd);
    atomic_store_explicit(&w->stopping, true, memory_order_release);
    if (w->thread_started) {
        if (w->stop_source) CFRunLoopSourceSignal(w->stop_source);
        CFRunLoopWakeUp(w->run_loop); pthread_join(w->worker, NULL);
        if (w->stop_source) CFRelease(w->stop_source);
        if (w->config_source) CFRelease(w->config_source);
        CFRelease(w->run_loop);
    }
    if (w->signal) event_free(w->signal);
    if (w->timer) event_free(w->timer);
    pthread_cond_destroy(&w->ready); pthread_mutex_destroy(&w->lock);
    free(w);
}
