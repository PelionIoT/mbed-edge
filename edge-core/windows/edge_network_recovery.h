/* SPDX-License-Identifier: Apache-2.0 */
#ifndef EDGE_NETWORK_RECOVERY_H
#define EDGE_NETWORK_RECOVERY_H
#include <stdbool.h>
#include <stdint.h>
struct event_base;
struct edge_network_watch;
enum { EDGE_NETWORK_ROUTE = 1, EDGE_NETWORK_ADDRESS = 2,
       EDGE_NETWORK_DNS = 4, EDGE_NETWORK_RESUME = 8, EDGE_NETWORK_RETRY = 16 };
typedef struct edge_network_policy {
    uint64_t changed_at, first_change, next_retry, last_attempt;
    unsigned pending, retry_ms;
    bool recovering, blocked;
} edge_network_policy;
void edge_network_policy_init(edge_network_policy *policy, uint64_t now);
void edge_network_policy_change(edge_network_policy *policy, uint64_t now, unsigned reason);
void edge_network_policy_cloud(edge_network_policy *policy, uint64_t now, bool connected, bool transient);
unsigned edge_network_policy_step(edge_network_policy *policy, uint64_t now);
struct edge_network_watch *edge_network_watch_start(struct event_base *base,
    void (*reconnect)(unsigned reason, void *context), void *context);
void edge_network_watch_cloud(struct edge_network_watch *watch, bool connected, bool transient);
void edge_network_watch_stop(struct edge_network_watch *watch);
#endif
