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
#include <event2/util.h>
#include "../edge_network_recovery.h"
#include "edge_network_config.h"

struct edge_network_watch {
    struct event *timer, *route_event;
    int route_fd, route_error;
    uint64_t last_tick, last_route_check;
    mach_timebase_info_data_t timebase;
    atomic_uint changes;
    atomic_bool stopping, configuration_dirty;
    pthread_t worker;
    pthread_mutex_t lock;
    pthread_cond_t ready;
    bool thread_started, worker_ready, worker_failed;
    CFRunLoopRef run_loop;
    edge_network_policy policy;
    void (*reconnect)(unsigned, void *);
    void *context;
};
/* These objects belong exclusively to the CF worker. No callback can outlive
 * this stack frame: its sources are removed before the worker exits/join ends. */
struct configuration_worker {
    struct edge_network_watch *watch;
    SCDynamicStoreRef store;
    CFRunLoopSourceRef store_source;
    CFArrayRef keys, patterns;
    CFDictionaryRef previous;
    io_connect_t power_connection;
    io_object_t power_notifier;
    IONotificationPortRef power_port;
    CFRunLoopSourceRef power_source;
    unsigned polls;
    int store_error;
};
static uint64_t now_ms(struct edge_network_watch *w)
{
    /* Unlike mach_absolute_time, continuous time includes system sleep. */
    return (uint64_t)((long double)mach_continuous_time() * w->timebase.numer /
                      w->timebase.denom / 1000000.0L);
}
static void changed(struct edge_network_watch *w, unsigned reason)
{ atomic_fetch_or_explicit(&w->changes, reason, memory_order_relaxed); }
static void store_changed(SCDynamicStoreRef store, CFArrayRef keys, void *context)
{
    (void)store; (void)keys;
    struct configuration_worker *worker = context;
    atomic_store_explicit(&worker->watch->configuration_dirty, true, memory_order_relaxed);
}
static void close_store(struct configuration_worker *worker)
{
    if (worker->store_source) {
        CFRunLoopRemoveSource(worker->watch->run_loop, worker->store_source, kCFRunLoopDefaultMode);
        CFRelease(worker->store_source); worker->store_source = NULL;
    }
    if (worker->store) { CFRelease(worker->store); worker->store = NULL; }
}
static void poll_configuration(CFRunLoopTimerRef timer, void *context)
{
    (void)timer;
    struct configuration_worker *worker = context;
    bool dirty = atomic_exchange_explicit(&worker->watch->configuration_dirty, false, memory_order_relaxed);
    if (++worker->polls % 5 && !dirty) return;
    if (!worker->store) {
        SCDynamicStoreContext sc_context = {0, worker, NULL, NULL, NULL};
        worker->store = SCDynamicStoreCreate(NULL, CFSTR("com.izuma.edge.network-recovery"), store_changed, &sc_context);
        if (worker->store && SCDynamicStoreSetNotificationKeys(worker->store, worker->keys, worker->patterns)) {
            worker->store_source = SCDynamicStoreCreateRunLoopSource(NULL, worker->store, 0);
            if (worker->store_source)
                CFRunLoopAddSource(worker->watch->run_loop, worker->store_source, kCFRunLoopDefaultMode);
        }
        if (worker->store && !worker->store_source)
            fprintf(stderr, "Network recovery: SystemConfiguration notifications unavailable; using 5-second snapshots.\n");
    }
    CFDictionaryRef raw = worker->store ? SCDynamicStoreCopyMultiple(worker->store, worker->keys, worker->patterns) : NULL;
    CFDictionaryRef snapshot = raw ? edge_macos_network_snapshot(raw) : NULL;
    if (raw) CFRelease(raw);
    if (!snapshot) {
        int error = SCError();
        if (!error) error = -1;
        if (!worker->store_error || worker->store_error != error)
            fprintf(stderr, "Network recovery: cannot inspect DNS/network configuration (SCError=%d); retrying.\n", error);
        worker->store_error = error;
        close_store(worker); /* Re-establish the session after a configd restart. */
        return;             /* Failure is not an empty/healthy snapshot. */
    }
    if (worker->store_error) {
        fprintf(stderr, "Network recovery: DNS/network configuration inspection restored.\n");
        worker->store_error = 0;
    }
    if (worker->previous && !CFEqual(worker->previous, snapshot)) changed(worker->watch, EDGE_NETWORK_DNS);
    if (worker->previous) CFRelease(worker->previous);
    worker->previous = snapshot;
}
static void power_changed(void *context, io_service_t service, natural_t type, void *argument)
{
    (void)service;
    struct configuration_worker *worker = context;
    if (type == kIOMessageCanSystemSleep || type == kIOMessageSystemWillSleep) {
        /* Never delay or veto sleep while waiting for DNS/cloud work. */
        IOAllowPowerChange(worker->power_connection, (long)(intptr_t)argument);
    } else if (type == kIOMessageSystemHasPoweredOn) {
        changed(worker->watch, EDGE_NETWORK_RESUME);
        atomic_store_explicit(&worker->watch->configuration_dirty, true, memory_order_relaxed);
    }
}
static void *configuration_thread(void *context)
{
    struct edge_network_watch *w = context;
    struct configuration_worker worker = {0};
    worker.watch = w;
    const void *keys[] = {CFSTR("State:/Network/Global/IPv4"), CFSTR("State:/Network/Global/IPv6"), CFSTR("State:/Network/Global/DNS")};
    const void *patterns[] = {
        CFSTR("State:/Network/Service/[^/]+/(IPv4|IPv6|DNS)"),
        CFSTR("State:/Network/Interface/[^/]+/(Link|IPv4|IPv6)")
    };
    worker.keys = CFArrayCreate(NULL, keys, sizeof(keys) / sizeof(keys[0]), &kCFTypeArrayCallBacks);
    worker.patterns = CFArrayCreate(NULL, patterns, sizeof(patterns) / sizeof(patterns[0]), &kCFTypeArrayCallBacks);
    CFRunLoopRef loop = CFRunLoopGetCurrent();
    pthread_mutex_lock(&w->lock);
    w->run_loop = (CFRunLoopRef)CFRetain(loop);
    pthread_mutex_unlock(&w->lock);
    poll_configuration(NULL, &worker); /* Establish baseline without reconnecting. */
    worker.power_connection = IORegisterForSystemPower(&worker, &worker.power_port, power_changed, &worker.power_notifier);
    if (worker.power_connection && worker.power_port) {
        worker.power_source = IONotificationPortGetRunLoopSource(worker.power_port);
        if (worker.power_source) CFRunLoopAddSource(loop, worker.power_source, kCFRunLoopDefaultMode);
    }
    if (!worker.power_source) {
        /* Unscheduled power callbacks would miss sleep acknowledgements. */
        if (worker.power_notifier) IODeregisterForSystemPower(&worker.power_notifier);
        worker.power_notifier = 0;
        if (worker.power_port) IONotificationPortDestroy(worker.power_port);
        worker.power_port = NULL;
        if (worker.power_connection) IOServiceClose(worker.power_connection);
        worker.power_connection = 0;
    }
    fprintf(stderr, "Network recovery: macOS DNS=%s power=%s; configuration poll=5s.\n",
            worker.store_source ? "notifications" : "polling",
            worker.power_source ? "notifications" : "continuous-clock fallback");
    CFRunLoopTimerContext timer_context = {0, &worker, NULL, NULL, NULL};
    CFRunLoopTimerRef timer = CFRunLoopTimerCreate(NULL, CFAbsoluteTimeGetCurrent() + 1.0,
                                                  1.0, 0, 0, poll_configuration, &timer_context);
    if (timer) CFRunLoopAddTimer(loop, timer, kCFRunLoopDefaultMode);
    pthread_mutex_lock(&w->lock);
    w->worker_failed = timer == NULL;
    w->worker_ready = true;
    pthread_cond_signal(&w->ready);
    pthread_mutex_unlock(&w->lock);
    /* A bounded run prevents a stop-before-run race from hanging pthread_join. */
    while (timer && !atomic_load_explicit(&w->stopping, memory_order_acquire))
        CFRunLoopRunInMode(kCFRunLoopDefaultMode, 1.0, false);
    if (timer) { CFRunLoopTimerInvalidate(timer); CFRelease(timer); }
    if (worker.power_notifier) IODeregisterForSystemPower(&worker.power_notifier);
    if (worker.power_source) CFRunLoopRemoveSource(loop, worker.power_source, kCFRunLoopDefaultMode);
    if (worker.power_port) IONotificationPortDestroy(worker.power_port);
    if (worker.power_connection) IOServiceClose(worker.power_connection);
    close_store(&worker);
    if (worker.previous) CFRelease(worker.previous);
    CFRelease(worker.keys); CFRelease(worker.patterns);
    return NULL;
}
static void route_read(evutil_socket_t descriptor, short events, void *context)
{
    (void)events;
    struct edge_network_watch *w = context;
    unsigned changes = 0;
    /* Bound work per event-loop turn so a route flood cannot starve shutdown. */
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
    if (changes & EDGE_MACOS_NETWORK_RECHECK)
        atomic_store_explicit(&w->configuration_dirty, true, memory_order_relaxed);
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
        if (error != w->route_error) fprintf(stderr, "Network recovery: routing notifications unavailable (errno=%d); retrying.\n", error);
        if (w->route_event) { event_free(w->route_event); w->route_event = NULL; }
        if (w->route_fd >= 0) close(w->route_fd);
        w->route_fd = -1;
    } else fprintf(stderr, "Network recovery: routing notifications %s.\n", w->route_error ? "restored" : "enabled");
    w->route_error = error;
}
static void tick(evutil_socket_t descriptor, short events, void *context)
{
    (void)descriptor; (void)events;
    struct edge_network_watch *w = context;
    uint64_t now = now_ms(w);
    unsigned reasons = atomic_exchange_explicit(&w->changes, 0, memory_order_relaxed);
    if (now - w->last_tick > 30000) reasons |= EDGE_NETWORK_RESUME;
    w->last_tick = now;
    if (w->route_fd < 0 && now - w->last_route_check >= 5000) {
        open_route_watch(w); w->last_route_check = now;
    }
    if (reasons) edge_network_policy_change(&w->policy, now, reasons);
    unsigned reason = edge_network_policy_step(&w->policy, now);
    if (reason) w->reconnect(reason, w->context);
}
struct edge_network_watch *edge_network_watch_start(struct event_base *base,
    void (*reconnect)(unsigned, void *), void *context)
{
    if (!base || !reconnect) return NULL;
    struct edge_network_watch *w = calloc(1, sizeof(*w));
    if (!w) return NULL;
    w->route_fd = -1; w->reconnect = reconnect; w->context = context;
    atomic_init(&w->changes, 0); atomic_init(&w->stopping, false);
    atomic_init(&w->configuration_dirty, true);
    if (mach_timebase_info(&w->timebase) != KERN_SUCCESS || !w->timebase.denom) { free(w); return NULL; }
    if (pthread_mutex_init(&w->lock, NULL)) { free(w); return NULL; }
    if (pthread_cond_init(&w->ready, NULL)) { pthread_mutex_destroy(&w->lock); free(w); return NULL; }
    w->last_tick = now_ms(w); w->last_route_check = w->last_tick;
    edge_network_policy_init(&w->policy, w->last_tick);
    w->timer = event_new(base, -1, EV_PERSIST, tick, w);
    struct timeval interval = {1, 0};
    if (!w->timer || event_add(w->timer, &interval)) { edge_network_watch_stop(w); return NULL; }
    open_route_watch(w);
    if (pthread_create(&w->worker, NULL, configuration_thread, w)) { edge_network_watch_stop(w); return NULL; }
    w->thread_started = true;
    pthread_mutex_lock(&w->lock);
    while (!w->worker_ready) pthread_cond_wait(&w->ready, &w->lock);
    pthread_mutex_unlock(&w->lock);
    if (w->worker_failed) { edge_network_watch_stop(w); return NULL; }
    return w;
}
void edge_network_watch_cloud(struct edge_network_watch *w, bool connected, bool transient)
{ if (w) edge_network_policy_cloud(&w->policy, now_ms(w), connected, transient); }
void edge_network_watch_stop(struct edge_network_watch *w)
{
    if (!w) return;
    if (w->timer) event_free(w->timer);
    if (w->route_event) event_free(w->route_event);
    if (w->route_fd >= 0) close(w->route_fd);
    atomic_store_explicit(&w->stopping, true, memory_order_release);
    if (w->thread_started) {
        CFRunLoopStop(w->run_loop); CFRunLoopWakeUp(w->run_loop);
        pthread_join(w->worker, NULL);
        CFRelease(w->run_loop);
    }
    pthread_cond_destroy(&w->ready); pthread_mutex_destroy(&w->lock);
    free(w);
}
