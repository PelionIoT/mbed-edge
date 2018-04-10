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

#ifndef INCLUDE_EDGE_COMMON_H_
#define INCLUDE_EDGE_COMMON_H_

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <event2/buffer.h>

#include "edge-rpc/rpc.h"
#include "pal.h"

typedef struct pt_device pt_device_t;

/**
 * \defgroup EDGE_COMMON mbed Edge Core and protocol translator common definitions.
 * @{
 */

/** \file edge_common.h
 * \brief This file describes the common functions that both Mbed Edge and the
 * protocol translator needs for successful communication.
 *
 * The connection and program context structures are defined here to align both sides
 * of the connection to work in similar way. The underlying mechanism for passing
 * bytes between Mbed Cloud and the protocol translator is a full-duplex non-blocking
 * TCP socket connection provided by the libevent-library.
 *
 * The protocol for framing messages is frame stream and it uses the fstrm-library. It contains the
 * simple means to do the handshake between communicating parties and to synchronize both to
 * accept length-delimited frames. The frame stream between the parties is bi-directional
 * and both sides can act as clients sending requests and as servers receiving requests.
 */

/**
 * \brief A function prototype for calling the client code when the connection is ready for passing messages
 * \param connection The connection which is ready.
 * \param userdata The user supplied data to pass back when the handler is called.
 */
typedef void (*pt_connection_ready_cb)(struct connection *connection, void *userdata);

/**
 * \brief A function prototype for calling the client code when the connection is shutting down
 * \param connection The connection reference of the protocol translator client connection.
 * \param userdata The user supplied data to pass back when the handler is called.
 */
typedef void (*pt_connection_shutdown_cb)(struct connection **connection, void *userdata);

/**
 * \brief Function pointer type definition for handling received message from Mbed Edge Core.
 *
 * The callbacks are run on the same thread as the event loop of the protocol translator client.\n
 * If the related functionality of the callback does some long processing the processing
 * must be moved to worker thread.\n
 * If the processing is run directly in the callback it will block the event loop and therefore it
 * will block the whole protocol translator.
 *
 * \param connection The connection which this write originates.
 * \param device_id The device ID to write the data.
 * \param object_id The object ID to write the data.
 * \param instance_id The instance ID to write the data.
 * \param resource_id The resource ID to write the data.
 * \param operation The operation of the write.
 * \param value The pointer to byte data to write.
 * \param value_size The length of the data.
 * \param userdata The pointer to user supplied data from `pt_client_start`.
 *
 * \return Returns 0 on success and non-zero on failure.
 */
typedef int (*pt_received_write_handler)(struct connection *connection,
                                         const char *device_id, const uint16_t object_id,
                                         const uint16_t instance_id,
                                         const uint16_t resource_id,
                                         const unsigned int operation,
                                         const uint8_t *value, const uint32_t value_size,
                                         void *userdata);

/**
 * \brief A structure to hold the callbacks of the protocol translator
 */
typedef struct protocol_translator_callbacks {
  pt_connection_ready_cb connection_ready_cb;
  pt_received_write_handler received_write_cb;
  pt_connection_shutdown_cb connection_shutdown_cb;
} protocol_translator_callbacks_t;

/**
 * \brief Enumeration of the connection state.
 */
typedef enum {
    /**
     * Connection initiator state when starting the handshake.
     * In this state, the connection initiator writes the READY control frame to the receiver.
     */
    CONNECTION_STATE_WRITING_CONTROL_READY,
    /**
     * Connection initiator state when it has written the READY control frame to the receiver.
     * In this state, the connection initiator writes the START control frame to the receiver.
     * The connection initiator is expecting to receive the ACCEPT control frame.
     */
    CONNECTION_STATE_READING_CONTROL_ACCEPT,
    /**
     * Connection receiver state when it has initiated the TCP socket with the connection initiator.
     * In this state, the connection receiver writes the ACCEPT control frame to the connection initiator.
     * The connection receiver is expecting to receive the READY control frame.
     */
    CONNECTION_STATE_READING_CONTROL_READY,
    /**
     * Connection receiver state when it has received the READY control frame.
     * The connection receiver is expecting to receive the START control frame.
     */
    CONNECTION_STATE_READING_CONTROL_START,
    /**
     * Connection initiator state when it has written the STOP control frame to the receiver.
     * The connection initiator is expecting to receive the FINISH control frame.
     */
    CONNECTION_STATE_READING_CONTROL_FINISH,
    /**
     * Connection initiator state when it has received the ACCEPT control frame.
     * The connection initiator is ready to pass and receive data frames.
     */
    CONNECTION_STATE_DATA,
    /**
     * When the connection is closed and no more frames can be passed between parties.
     */
    CONNECTION_STATE_STOPPED
} connection_state;

/**
 * \brief Timestamp string length. Timestamp format: YYYY-MM-DD hh:mm:ss with one trailing whitespace (20 chars + trailing nil)
 */
#define TIMESTAMP_SIZE 21

/**
 * \brief The static char buffer used for storing the timestamp prefix for the mbed-trace logger.
 */
extern char *timestamp_prefix;

/**
 * \brief The mutex used for ensuring the thread safety of the mbed-trace logger.
 */
extern palMutexID_t TraceMutex;

typedef struct protocol_translator {
    char* name;
    bool registered;
    int id;
} protocol_translator_t;

struct ctx_data;
struct connection;

struct context {
    const char *hostname;
    int port;
    evutil_socket_t listen_fd;
    struct event_base *ev_base;
    struct evconnlistener *ev_connlistener;
    struct event *ev_sighup;
    size_t json_flags;
    struct ctx_data *ctx_data;
};

struct connection {
    struct context *ctx;
    connection_state state;
    uint32_t len_frame_payload;
    uint32_t len_frame_total;
    size_t len_buffer;
    struct bufferevent *bev;
    struct evbuffer *ev_input;
    struct evbuffer *ev_output;
    struct fstrm_control *control;
    protocol_translator_t *protocol_translator;
    const protocol_translator_callbacks_t *protocol_translator_callbacks;
    void *userdata;
};

/*
 * \brief Create a new protocol translator
 */
protocol_translator_t *edge_common_create_protocol_translator();

/**
 * \brief Initialize the libevent event callback to handle a generic event from libevent.
 * \param event A callback handler.
 */
void edge_common_init_event_cb(void (*event_cb)(struct bufferevent *bev, short events, void *arg));

/**
 * \brief The function definition for setting the underlying socket options.
 * \param fd The socket file descriptor.
 * \return 0 if the setting of socket options succeeded.\n
 *         1 if the setting of socket options failed.
 */
int edge_common_set_socket_options(evutil_socket_t fd);

/**
 * \brief The function definition for configuring libevent.
 * \return 0 if the configuring succeeded.\n
 *         1 if confuring failed.
 */
int edge_common_configure_libevent();

/**
 * \brief Deallocate connections.
 * \param connection The array to deallocate.
 */
void edge_common_connection_destroy(struct connection **connection);

/**
 * \brief Match the expected content type to content type set in the connection.
 * The expected content type is "jsonrpc".
 * \return True if content type is ok.\n
 *         False if content is not ok.
 */
bool edge_common_match_ct(struct connection *connection);

/**
 * \brief Writes the current control frame to connection.
 * \param connection The connection to which to write the control frame.
 * \return True if control frame write succeeded.\n
 *         False if control frame write failed.
 */
bool edge_common_write_control_frame(struct connection *connection);

/**
 * \brief Process the received control frame from the connection.
 *
 * \param connection The connection from which the control frame is read.
 * \param connection_destroyed
 *        This value is set to true if the connection was destroyed during the control frame processing.\n
 *        False if the connection wasn't destroyed.
 */
bool edge_common_process_control_frame(struct connection *connection, bool *connection_destroyed);

/**
 * \brief Specific implementation for processing a data frame.
 *        The PT client and Edge Core have different implementation for this.
 *
 * \param connection The connection which is receiving the data frame.
 * \param connection_destroyed
 *        This value is set to true if the connection was destroyed during the specific data frame processing.\n
 *        False if the connection wasn't destroyed.
 */
void edge_common_process_data_frame_specific(struct connection *connection, bool *connection_destroyed);

/**
 * \brief Common implementation for processing a data frame.
 *        This function is shared by the PT Client and Edge Core.
 *
 * \param connection The connection which is receiving the data frame.
 * \param connection_destroyed
 *        This value is set to true if the connection was destroyed during the data frame processing.\n
 *        False if the connection wasn't destroyed.
 */
void edge_common_process_data_frame(struct connection *connection, bool *connection_destroyed);

/**
 * \brief Libevent read callback definition.
 *
 * \param bev The buffer event that triggered the read callback.
 * \param ctx The user-supplied context when the read callback was assigned to the connection.\n
 *            In Mbed Edge and the protocol translator, this is the current connection structure.
 */
void edge_common_read_cb(struct bufferevent *bev, void *ctx);

/**
 * \brief Core service and protocol translator data frame write function.
 *        This will allocate the data frame and set needed values there and then
 *        forward the data to underlying transport mechanism.
 *
 * \param connection The connection to write the data for.
 * \param data The byte buffer to write to connection.
 * \param len_data The length of the data to write.
 */
bool edge_common_write_data_frame(struct connection *connection, char *data, size_t len_data);

/**
 * \brief Constructs and sends the message. If successfully sent, adds the message entry
 * to RPC message entry list which is used to match the requests to response messages.
 *
 * \param connection The connection to write the data for.
 * \param message The json message to deserialize.
 * \param success_handler The internal success handler to be called for successful responses.
 * \param failure_handler The internal failure handler to be called for failure responses.
 * \param free_func The internal free function to be called after success or failure callback has been called
 * \param customer_callback_context The user-supplied customer callback context data pointer that is passed to the callback handlers.
 * \return 0 if the message was successfully sent.\n
 *        -1 if the message couldn't be allocated.\n
 *        -2 if the message couldn't be sent.
 */
int32_t edge_common_construct_and_send_message(struct connection *connection,
                                               json_t *message,
                                               rpc_response_handler success_handler,
                                               rpc_response_handler failure_handler,
                                               rpc_free_func free_func,
                                               void *customer_callback_ctx);

/**
 * \brief Writes a STOP control frame using given connection. The recipient should by respond sending the FINISH
 * control frame.
 *
 * \note This is used by both the server and the client when they want to initiate a graceful disconnect.
 *
 * \param connection The connection which is used to write the STOP control frame.
 * \return True if the frame was succesfully sent.\n
 *         False if the frame sending failed.
 */
bool edge_common_write_stop_frame(struct connection *connection);

/**
 * \brief The function to initialize the mutex for mbed-trace.
 */
void trace_mutex_init();

/**
 * \brief The function to implement the mutex locking for mbed-trace.
 */
void trace_mutex_wait();

/**
 * \brief The function to implement the mutex releasing for mbed-trace.
 */
void trace_mutex_release();

/**
 * \brief The function to create timestamp prefixes for mbed-trace.
 *
 * \param size The length of the message body.
 * \return A pointer to timestamp prefix string.
 */
char *trace_prefix(size_t size);

/**
 * \brief Sends the given data using the given connection.
 *
 * \param connection is the connection to use.
 * \param data is pointer to the data that needs to be sent
 * \param size is the size of the data in bytes.
 * \return True if the data was sent successfully.\n
 *         False if the sending failed.
 */
bool send_frame(struct connection *connection, const void *data, size_t size);

/**
 * @}
 * Close EDGE_COMMON Doxygen group definition
 */

#endif /* INCLUDE_EDGE_COMMON_H_ */
