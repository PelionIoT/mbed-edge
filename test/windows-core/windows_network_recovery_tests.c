/* SPDX-License-Identifier: Apache-2.0 */
#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>
#include <windows.h>
#include <event2/event.h>
#include "edge_network_recovery.h"
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "line %d: %s\n", __LINE__, #x); exit(1); } } while (0)
static void unexpected(unsigned reason, void *context)
{ (void)reason; (void)context; CHECK(0); }
int main(void)
{
    edge_network_policy p;
    edge_network_policy_init(&p, 1000);
    edge_network_policy_cloud(&p, 1001, true, false);
    CHECK(!edge_network_policy_step(&p, 1000000)); /* Healthy clients remain undisturbed. */
    edge_network_policy_change(&p, 1000000, EDGE_NETWORK_ROUTE);
    edge_network_policy_change(&p, 1001000, EDGE_NETWORK_DNS);
    CHECK(!edge_network_policy_step(&p, 1002000));
    CHECK(edge_network_policy_step(&p, 1003000) == (EDGE_NETWORK_ROUTE | EDGE_NETWORK_DNS));
    CHECK(!edge_network_policy_step(&p, 1004000));
    CHECK(edge_network_policy_step(&p, 1018000) == EDGE_NETWORK_RETRY);
    CHECK(!edge_network_policy_step(&p, 1047999));
    CHECK(edge_network_policy_step(&p, 1048000) == EDGE_NETWORK_RETRY);
    for (unsigned i = 0; i < 20; ++i) {
        CHECK(edge_network_policy_step(&p, p.next_retry) == EDGE_NETWORK_RETRY);
        CHECK(p.retry_ms <= 120000);
    }
    uint64_t now = p.last_attempt + 1;
    edge_network_policy_change(&p, now, EDGE_NETWORK_RESUME);
    CHECK(!edge_network_policy_step(&p, now + 2000)); /* Rate limit noisy notifications. */
    CHECK(edge_network_policy_step(&p, now + 10000) == EDGE_NETWORK_RESUME);
    CHECK(p.next_retry == now + 25000); /* Resume resets a long outage's backoff. */
    edge_network_policy_cloud(&p, now + 10001, true, false);
    CHECK(!edge_network_policy_step(&p, now + 1000000));
    edge_network_policy_cloud(&p, now + 1000000, false, true);
    CHECK(!edge_network_policy_step(&p, now + 1014999));
    CHECK(edge_network_policy_step(&p, now + 1015000) == EDGE_NETWORK_RETRY);
    edge_network_policy_cloud(&p, now + 1015001, false, false);
    edge_network_policy_change(&p, now + 1015002, EDGE_NETWORK_ROUTE);
    CHECK(!edge_network_policy_step(&p, now + 2000000)); /* No auth/config retry loop. */
    edge_network_policy_init(&p, 1000);
    edge_network_policy_cloud(&p, 2000, false, true);
    CHECK(edge_network_policy_step(&p, 17000) == EDGE_NETWORK_RETRY);
    edge_network_policy_init(&p, 1000);
    edge_network_policy_cloud(&p, 1001, true, false);
    for (unsigned i = 0; i < 10; ++i) {
        edge_network_policy_change(&p, 10000 + i * 1000, EDGE_NETWORK_ADDRESS);
        CHECK(!edge_network_policy_step(&p, 10000 + i * 1000));
    }
    CHECK(edge_network_policy_step(&p, 20000) == EDGE_NETWORK_ADDRESS); /* Debounce has an upper bound. */
    /* Register/cancel actual native watchers repeatedly; teardown must not race callbacks. */
    WSADATA sockets; CHECK(!WSAStartup(MAKEWORD(2,2), &sockets));
    struct event_base *base = event_base_new(); CHECK(base);
    for (int i = 0; i < 10; ++i) {
        struct edge_network_watch *watch = edge_network_watch_start(base, unexpected, NULL); CHECK(watch);
        edge_network_watch_cloud(watch, true, false);
        event_base_loop(base, EVLOOP_NONBLOCK);
        edge_network_watch_stop(watch);
    }
    event_base_free(base); WSACleanup();
    puts("Network recovery policy, debounce, bounded retry, authentication guard and native watcher lifecycle passed.");
    return 0;
}
