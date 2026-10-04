/* SPDX-License-Identifier: Apache-2.0 */
#ifndef EDGE_LISTENER_STATUS_H
#define EDGE_LISTENER_STATUS_H
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <jansson.h>

typedef struct {
    bool available, enabled, listening;
    const char *address;
} edge_listener_entry;

/* Owned by the server event thread. Addresses remain valid until shutdown. */
typedef struct edge_listener_status {
    edge_listener_entry http, tcp, af_unix, named_pipe;
    uint64_t started_ms;
    unsigned pipe_max_clients, pipe_connected_clients, pipe_client_sid_count;
    struct edge_pt_pipe_listener *pipe_listener;
} edge_listener_status;

json_t *edge_listener_status_json(const edge_listener_status *state, uint64_t now_ms,
    uint32_t process_id, unsigned registered_pts, unsigned registered_devices);
struct evhttp_bound_socket;
/* Read the bound socket, including the OS-selected port when port 0 was used. */
bool edge_listener_http_address(struct evhttp_bound_socket *socket, char *address, size_t capacity);
#endif
