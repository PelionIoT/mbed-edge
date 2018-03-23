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

#ifndef RPC_H_
#define RPC_H_

#include <stdbool.h>

#include "jsonrpc/jsonrpc.h"
#include "common/default_message_id_generator.h"

/**
 * \defgroup EDGE_RPC Mbed Core Edge and protocol translator RPC framework definitions.
 * @{
 */

/**
 * \file rpc.h
 * \brief High level API for RPC implementation of Mbed Core Edge and protocol translator.
 *
 * Defines the functions for passing RPC requests and handling responses to sent requests.
 * The implementation of this API must keep track of the request identifiers for matching the
 * responses to the requests they belong to.
 *
 * The RPC protocol is JSONRPC 2.0 and the data is UTF-8 encoded.
 * Data must not be NUL-terminated.
 */

/**
 * \brief Connection abstraction for implementations to define.
 */
typedef struct connection connection_;

struct json_message_t {
    char *data;
    size_t len;
    struct connection *connection;
};

/**
 * \brief Allocate base request
 * \return The pointer to json_t message
 */
json_t* allocate_base_request(const char* method);

/**
 * \brief Allocate the `json_message_t` structure.
 * \return The allocated `json_message_t` structure.
 */
struct json_message_t* alloc_json_message_t(char* data, size_t len, struct connection *connection);

/**
 * \brief Deallocate `json_message_t`.
 * Deallocates also the contained byte data.
 */
void deallocate_json_message_t(struct json_message_t *msg);

/*
 * \brief The function prototype for the response handler callbacks.
 * \param response The full json response object.
 * \param userdata The user-supplied context data pointer.
 */
typedef void (*rpc_response_handler)(json_t *response, void* userdata);

/*
 * \brief The function prototype for free callbacks
 * \param userdata The user-supplied context data pointer (to be freed)
 */
typedef void (*rpc_free_func)(void* userdata);

/**
 * \brief The function prototype for the underlying transport mechanism of the write function.
 * \param connection The connection to which to write the data.
 * \param data The byte data to write.
 * \param len The length of the data to write.
 * \return True if the write was successful, false if it failed.
 */
typedef bool (*write_func)(struct connection *connection, char* data, size_t len);

/**
 * \brief Get the message list size
 * \return The number of messages in the list
 */
int rpc_message_list_size();

/**
 * \brief Check if message list is empty
 * \return Returns true if list is empty, false if list contains elements.
 */
bool rpc_message_list_is_empty();

/**
 * \brief set the message id generation function
 * \param generate_msg_id is a function pointer to implementing function
 */
void rpc_set_generate_msg_id(generate_msg_id generate_msg_id);

/**
 * \brief Register json RPC handler methods.
 * \param method_table[] The `json_rpc_method_entry_t` entries for RPC.
 */
void rpc_init(struct jsonrpc_method_entry_t method_table[]);

/**
 * \brief Handles the sending of a json-rpc message, generates an ID for the message.
 * \param message The json message to deserialize.
 * \param success_handler The internal success handler to be called for successful responses.
 * \param failure_handler The internal failure handler to be called for failure responses.
 * \param free_func The internal free function to be called after success or failure callback has been called
 * \param request_context The user-supplied request context data pointer that is passed to the callback handlers.
 * \param returned_message_entry If the message can successfully allocated, a message entry is returned.
 * \param data The serialized JSON message.
 * \param message_id The message identifier for reference. Ownership is transferred to caller.
 * \return 0 for success.
 *         1 for failure.
 */
int rpc_construct_message(json_t *message,
                          rpc_response_handler success_handler,
                          rpc_response_handler failure_handler,
                          rpc_free_func free_func,
                          void *request_context,
                          void **returned_message_entry,
                          char **data,
                          char **message_id);

/**
 * \brief Handles the incoming raw json-rpc string from the connection.
 * \param data The byte data buffer of received data.
 * \param len The length of the byte data buffer.
 * \param connection The connection to which the data belongs. (TBD how about: The connection containing the data.)
 * \param write_func The function to use for writing data back.
 * \param protocol_error The flag is set to true if the frame data cannot be parsed. Otherwise it is set to false.
 */
int rpc_handle_message(char *data,
                       size_t len,
                       struct connection *connection,
                       write_func write_function,
                       bool *protocol_error);

/*
 * \brief Destroys all messages that are waiting for processing.
 */
void rpc_destroy_messages();

/**
 * \brief Adds the message_entry to rpc message entry list. It's used to match the request messages
 * to reponses. The messsage_entry is typically created by calling rpc_construct_message.
 * \param message_entry The message to add to the list.
 */
void rpc_add_message_entry_to_list(void *message_entry);

/**
 * \brief Remove the message from message list by the identifier.
 * \param message_id The id for message to remove.
 * \return The removed message
 */
void remove_message_for_id(const char *message_id);

/**
 * \brief Deallocates the message_entry. The client needs to deallocate it manually by calling this function if the
 * message can't be sent.
 * \param message_entry The message that is to be deallocated and which is typically created by calling
 * rpc_construct_message.
 */
void rpc_dealloc_message_entry(void *message_entry);

/**
 * @}
 * Close EDGE_RPC Doxygen group definition
 */

#endif /* RPC_H_ */
