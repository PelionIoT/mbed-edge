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
#include "edge-core/client_type.h"

/**
 * \defgroup EDGE_SERVER Edge functionality and RPC API.
 * @{
 */

/** \file server.h
 * \brief The server side entry definitions of Edge.
 */

struct ctx_data;

struct context {
    struct event_base *ev_base;
    struct event *ev_sighup;
    const char *socket_path;
    size_t json_flags;
    struct ctx_data *ctx_data;
};

typedef struct connection connection_t;
typedef int32_t connection_id_t;

/**
 * \brief Enumeration of Edge statuses.
 */
typedef enum {
    /**
     * The status when Edge is connecting or reconnecting to Device Management.
     */
    EDGE_STATE_CONNECTING,
    /**
     * The status when Edge has a working connection with Device Management.
     */
    EDGE_STATE_CONNECTED,
    /**
     * The status when Edge has encountered an error with the connection to Device Management.
     */
    EDGE_STATE_ERROR
} edge_state;

/**
 * \brief The ID for the protocol translator object stored in Device Management Client.
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
    connection_t *conn;
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
 * \brief Initializes the connection structure between Edge and the connected
 * protocol translator.
 * \param ctx The program context.
 * \param client_data the client data.
 * \return The connection structure containing the connection related data.
 */
struct connection* connection_init(struct context *ctx, client_data_t *client_data);

/**
 * \brief Deallocate the connection structure reserved memory.
 * \param connection The connection to be deallocated.
 * \return the number of endpoints removed.
 */
uint32_t connection_free(struct connection *connection);

/**
 * \brief Create and start Edge eventloop.
 * \param ctx The program context.
 * \param http_port The port of the HTTP server to listen to.
 */
bool create_server_event_loop(struct context *ctx, int http_port);

/**
 * \brief Finds the connection given the connection ID.
 * \param connection_id ID of the connection.
 * \return The connection if the connection is found.
 *         Otherwise it returns NULL.
 */
connection_t *srv_comm_find_connection(connection_id_t connection_id);

/**
 * @}
 * Close EDGE_SERVER Doxygen group definition
 */

#endif /* SERVER_H_ */
