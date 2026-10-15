/* SPDX-License-Identifier: Apache-2.0 */
#include "edge_network_recovery.h"
#include <string.h>
void edge_network_policy_init(edge_network_policy *p, uint64_t now)
{
    memset(p, 0, sizeof(*p));
    p->retry_ms = 15000;
    p->recovering = true;
    p->next_retry = now + 120000; /* Allow the initial bootstrap/registration. */
}
void edge_network_policy_change(edge_network_policy *p, uint64_t now, unsigned reason)
{
    if (!p->pending) p->first_change = now;
    p->pending |= reason;
    p->changed_at = now;
    p->retry_ms = 15000; /* A new network/resume invalidates the old backoff. */
}
void edge_network_policy_cloud(edge_network_policy *p, uint64_t now, bool connected, bool transient)
{
    if (connected) {
        p->recovering = p->blocked = false;
        p->retry_ms = 15000;
    } else if (!transient) {
        p->blocked = true; /* Configuration/authentication errors need intervention. */
        p->recovering = false;
    } else if (!p->blocked && !p->recovering) {
        p->recovering = true;
        p->next_retry = now + p->retry_ms;
    } else if (!p->blocked && p->last_attempt == 0) {
        /* The first transport failure should not wait for the startup deadline. */
        if (p->next_retry > now + p->retry_ms) p->next_retry = now + p->retry_ms;
    }
}
unsigned edge_network_policy_step(edge_network_policy *p, uint64_t now)
{
    if (p->blocked) { p->pending = 0; return 0; }
    unsigned reason = 0;
    if (p->pending && (now - p->changed_at >= 2000 || now - p->first_change >= 10000))
        reason = p->pending;
    if (!reason && p->recovering && now >= p->next_retry) reason = EDGE_NETWORK_RETRY;
    if (!reason || (p->last_attempt && now - p->last_attempt < 10000)) return 0;
    p->pending = 0;
    p->last_attempt = now;
    p->recovering = true;
    p->next_retry = now + p->retry_ms;
    if (p->retry_ms < 120000) p->retry_ms *= 2;
    if (p->retry_ms > 120000) p->retry_ms = 120000;
    return reason;
}
