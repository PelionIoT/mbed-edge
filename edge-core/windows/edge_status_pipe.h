/* SPDX-License-Identifier: Apache-2.0 */
#ifndef EDGE_WINDOWS_STATUS_PIPE_H
#define EDGE_WINDOWS_STATUS_PIPE_H

#include <stdbool.h>
#include <stddef.h>

#ifdef EDGE_STATUS_PIPE_TEST_NAMESPACE
/* Only the standalone test target defines this; live service IPC stays fixed. */
#define EDGE_STATUS_PIPE_NAME "\\\\.\\pipe\\IzumaEdgeCoreStatusTest-" EDGE_STATUS_PIPE_TEST_NAMESPACE
#define EDGE_STATUS_PIPE_NAME_W L"\\\\.\\pipe\\IzumaEdgeCoreStatusTest-" EDGE_STATUS_PIPE_TEST_NAMESPACE_W
#else
#define EDGE_STATUS_PIPE_NAME "\\\\.\\pipe\\IzumaEdgeCoreStatus"
#define EDGE_STATUS_PIPE_NAME_W L"\\\\.\\pipe\\IzumaEdgeCoreStatus"
#endif

struct event_base;
struct edge_status_pipe;

/* Called on the Edge event thread; the returned JSON belongs to the pipe. */
typedef char *(*edge_status_snapshot_fn)(void *context);

struct edge_status_pipe *edge_status_pipe_start(struct event_base *base,
    edge_status_snapshot_fn snapshot, void *context);
void edge_status_pipe_stop(struct edge_status_pipe *listener);
bool edge_status_public_uri(const char *uri, char *result, size_t capacity);

#endif
