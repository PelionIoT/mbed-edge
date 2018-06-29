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

#ifndef SERVER_H_
#define SERVER_H_

#include "ns_list.h"

/**
 * \defgroup EDGE_SERVER Mbed Edge functionality and RPC API.
 * @{
 */

/** \file server.h
 * \brief The server side entry definitions of Mbed Edge.
 */

struct ctx_data;

struct context {
    struct event_base *ev_base;
    struct event *ev_sighup;
    const char *socket_path;
    size_t json_flags;
    struct ctx_data *ctx_data;
};

/**
 * \brief Enumeration of Mbed Edge statuses.
 */
typedef enum {
    /**
     * The status when Mbed Edge is connecting or reconnecting to Mbed Cloud.
     */
    EDGE_STATE_CONNECTING,
    /**
     * The status when Mbed Edge has a working connection with Mbed Cloud.
     */
    EDGE_STATE_CONNECTED,
    /**
     * The status when Mbed Edge has encountered an error with the connection to Mbed Cloud.
     */
    EDGE_STATE_ERROR
} edge_state;

/**
 * \brief The ID for the protocol translator object stored in Cloud Client.
 */
#define PROTOCOL_TRANSLATOR_OBJECT_ID 26241
/**
 * \brief The ID for the resource storing the protocol translator name in a protocol translator object.
 */
#define PROTOCOL_TRANSLATOR_OBJECT_NAME_RESOURCE_ID 0
/**
 * \brief The ID for the resource storing the number of endpoint devices in the protocol translator.
 */
#define PROTOCOL_TRANSLATOR_OBJECT_COUNT_RESOURCE_ID 1

struct connection_list_elem {
    struct connection *conn;
    ns_list_link_t link;
};

typedef NS_LIST_HEAD(struct connection_list_elem, link) connection_elem_list;

struct cloud_error {
    int error_code;
    char *error_description;
};

struct ctx_data {
    struct http_server *http_server;
    edge_state cloud_connection_status;
    struct cloud_error *cloud_error;
    connection_elem_list registered_translators;
    connection_elem_list not_accepted_translators;
    int registered_endpoint_limit;
    int registered_endpoint_count;
    bool rfs_customer_code_succeeded;
    bool exiting;
};

/**
 * \brief Initializes the connection structure between Mbed Edge and the connected
 * protocol translator.
 * \param ctx The program context.
 * \return The connection structure containing the connection related data.
 */
struct connection* connection_init(struct context *ctx);

/**
 * \brief Deallocate the connection structure reserved memory.
 * \param connection The connection to be deallocated.
 * \return the number of endpoints removed.
 */
uint32_t connection_free(struct connection *connection);

/**
 * \brief Create and start Mbed Edge eventloop.
 * \param ctx The program context.
 * \param http_port The port of the HTTP server to listen to.
 */
bool create_server_event_loop(struct context *ctx, int http_port);

/**
 * @}
 * Close EDGE_SERVER Doxygen group definition
 */

#endif /* SERVER_H_ */
