/* SPDX-License-Identifier: Apache-2.0 */
#ifndef EDGE_WINDOWS_PT_UNIX_H
#define EDGE_WINDOWS_PT_UNIX_H
#include <stdbool.h>
struct event_base;
struct lws_context;
struct edge_pt_unix_listener;
bool edge_pt_unix_path_valid(const char *path);
struct edge_pt_unix_listener *edge_pt_unix_start(struct event_base *base,
                                               struct lws_context *context,
                                               const char *path);
/* Call on the Edge event thread, before destroying the WebSocket context. */
void edge_pt_unix_stop(struct edge_pt_unix_listener *listener);
#endif
