/* SPDX-License-Identifier: Apache-2.0 */
#ifndef EDGE_WINDOWS_PT_PIPE_H
#define EDGE_WINDOWS_PT_PIPE_H
#include <stddef.h>
#include "edge_runtime_config.h"
#define EDGE_PT_PIPE_MAX_FRAME 65536u
struct event_base;
struct edge_pt_pipe_listener;
struct edge_pt_pipe_connection;
typedef struct {
    void *(*opened)(void *context, struct edge_pt_pipe_connection *peer);
    void (*received)(void *session, const char *data, size_t length);
    void (*closed)(void *session);
} edge_pt_pipe_callbacks;
struct edge_pt_pipe_listener *edge_pt_pipe_start(struct event_base *base,
    const edge_runtime_config *config, const edge_pt_pipe_callbacks *callbacks, void *context);
/* All entry points run on the Edge event thread. send takes ownership of data,
 * including on failure; successful enqueue returns zero, failure returns -1. */
int edge_pt_pipe_send(struct edge_pt_pipe_connection *peer, char *data, size_t length);
void edge_pt_pipe_close(void *peer);
void edge_pt_pipe_stop(struct edge_pt_pipe_listener *listener);
/* Established framing sessions; call on the server event thread. */
unsigned edge_pt_pipe_client_count(const struct edge_pt_pipe_listener *listener);
#endif
