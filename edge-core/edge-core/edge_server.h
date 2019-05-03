/*
 * ----------------------------------------------------------------------------
 * Copyright 2018 ARM Ltd.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ----------------------------------------------------------------------------
 */

#ifndef EDGE_SERVER_H
#define EDGE_SERVER_H

#include "edge-client/edge_client.h"
#include "edge-core/protocol_api_internal.h"
#include <pthread.h>
#include "libwebsockets.h"
#include "common/edge_mutex.h"

void edgeserver_exit_event_loop();
void *edgeserver_graceful_shutdown();
void edgeserver_rfs_customer_code_succeeded();
bool edgeserver_remove_protocol_translator_nodes();
int32_t edgeserver_get_number_registered_endpoints_limit();
int32_t edgeserver_get_number_registered_endpoints_count();
void edgeserver_change_number_registered_endpoints_by_delta(int32_t delta);
struct event_base *edge_server_get_base();
void edge_server_set_rfs_thread(pthread_t *thread);
connection_elem_list *edge_server_get_registered_translators();

/**
 * \brief May be called from any thread to send the response.
 *        Internally it sends a message to event loop where it checks that the
 *        connection is still valid and sends the response.
 */
void edge_server_construct_and_send_response_safe(connection_id_t connection_id,
                                                  json_t *response,
                                                  rpc_free_func free_func,
                                                  rpc_request_context_t *customer_callback_ctx);

/**
 * \brief The function to initialize the mutex for mbed-trace.
 */
void trace_mutex_init();

/**
 * \brief The function to destroys the mutex for mbed-trace.
 */
void trace_mutex_destroy();

/**
 * \brief The function to implement the mutex locking for mbed-trace.
 */
void trace_mutex_wait();

/**
 * \brief The function to implement the mutex releasing for mbed-trace.
 */
void trace_mutex_release();

#ifdef BUILD_TYPE_TEST

extern struct lws_protocols edge_server_protocols[];
/**
 * \brief The mutex used for ensuring the thread safety of the mbed-trace logger.
 */
extern struct context *g_program_context;
extern edgeclient_create_parameters_t edgeclient_create_params;
int testable_main(int argc, char **argv);
void shutdown_handler(evutil_socket_t s, short x, void * args);
bool parse_create_params(int argc, char **argv, edgeclient_create_parameters_t *create_params, bool *display_help);
void display_help();
void error_cb(int error_code, const char *error_description);
void register_cb(void);
void unregister_cb(void);
void edgeserver_set_number_registered_endpoints_limit(int32_t limit);
void create_program_context_and_data();
struct lws_context *initialize_libwebsocket_context(struct event_base *ev_base,
                                                    const char *edge_pt_socket,
                                                    struct lws_protocols protocols[],
                                                    int *lock_fd);
void clean_resources(struct lws_context *lwsc, const char *edge_pt_socket, int lock_fd);
void free_program_context_and_data();
void safe_response_callback(void *data);

#endif // end BUILD_TYPE_TEST

#endif // end EDGE_SERVER_H

