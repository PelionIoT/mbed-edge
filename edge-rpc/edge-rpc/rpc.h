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
#include <stdint.h>

#include "jsonrpc/jsonrpc.h"
#include "common/default_message_id_generator.h"

#include "common/edge_mutex.h"

/**
 * \defgroup EDGE_RPC Core Edge and protocol translator RPC framework definitions.
 * @{
 */

/**
 * \file rpc.h
 * \brief High level API for RPC implementation of Core Edge and protocol translator.
 *
 * Defines the functions for passing RPC requests and handling responses to sent requests.
 * The implementation of this API must keep track of the request identifiers for matching the
 * responses to the requests they belong to.
 *
 * The RPC protocol is JSONRPC 2.0 and the data is UTF-8 encoded.
 * Data must not be NULL terminated.
 */

struct connection;

/**
 * \brief Enum describing the JSON RPC method return codes.
 */
typedef enum {
    JSONRPC_RETURN_CODE_NO_RESPONSE = -1,
    JSONRPC_RETURN_CODE_SUCCESS = 0,
    JSONRPC_RETURN_CODE_ERROR = 1
} jsonrpc_method_return_code_e;

/**
 * \brief Describes customers request context. It can contain any data.
 */
struct rpc_request_context;
typedef struct rpc_request_context rpc_request_context_t;

extern edge_mutex_t rpc_mutex;
void rpc_init();
void rpc_deinit();

/**
 * \brief Allocate the base request.
 *
 * \return The pointer to `json_t` message
 */
json_t* allocate_base_request(const char* method);

/**
 * \brief Allocate the `json_message_t` structure.
 *
 * \return The allocated `json_message_t` structure.
 */
struct json_message_t* alloc_json_message_t(const char* data, size_t len, struct connection *connection);

/**
 * \brief Deallocate `json_message_t`.
 * Deallocates also the contained byte data.
 *
 * \param msg The JSON message structure to deallocate.
 */
void deallocate_json_message_t(struct json_message_t *msg);

/**
 * \brief The function prototype for response handler callbacks.
 *
 * \param response The full json response object.
 * \param userdata The user-supplied context data pointer.
 */
typedef void (*rpc_response_handler)(json_t *response, void *userdata);

/**
 * \brief The function prototype for free callbacks.
 *
 * \param userdata The user-supplied context data pointer (to be freed).
 */
typedef void (*rpc_free_func)(rpc_request_context_t* userdata);

/**
 * \brief The function prototype for the underlying transport mechanism of the write function.
 *
 * \param connection The connection to which to write the data.
 * \param data The byte data to write. Ownership of this data is transferred to write_func.
 * \param len The length of the data to write.
 * \return 0 if the write was successful.\n
 *         Non-zero if the write failed.
 */
typedef int (*write_func)(struct connection *connection, char* data, size_t len);

/**
 * \brief Get the message list size.
 *
 * \return The number of messages in the list
 */
int rpc_message_list_size();

/**
 * \brief Check if the message list is empty.
 *
 * \return True if the list is empty.\n
 *         False if the list contains elements.
 */
bool rpc_message_list_is_empty();

/**
 * \brief Set the message ID generation function.
 *
 * \param generate_msg_id A function pointer to the implementing function.
 */
void rpc_set_generate_msg_id(generate_msg_id generate_msg_id);

/**
 * \brief Handles the sending of a json-rpc message and generates an ID for the message.
 *
 * \param message The json message to deserialize.
 * \param success_handler The internal success handler to be called for successful responses.
 * \param failure_handler The internal failure handler to be called for failure responses.
 * \param free_func The internal free function to be called after a success or failure callback has been called.
 * \param request_context The user-supplied request context data pointer that is passed to the callback handlers.
 * \param connection The connection used to send this request message.
 * \param returned_message_entry If the message can be successfully allocated, a message entry is returned.
 * \param data The serialized JSON message.
 * \param data_len The size of the serialized JSON message.
 * \param message_id The message identifier for reference. The ownership is transferred to the caller.
 * \return 0 for success.\n
 *         1 for failure.
 */
int rpc_construct_message(json_t *message,
                          rpc_response_handler success_handler,
                          rpc_response_handler failure_handler,
                          rpc_free_func free_func,
                          rpc_request_context_t *request_context,
                          struct connection *connection,
                          void **returned_message_entry,
                          char **data,
                          size_t *data_len,
                          char **message_id);

/**
 * \brief Used to create the json-rpc response.
 *
 * \param response The json message to serialize.
 * \param data The serialized JSON message.
 * \param data_len The size of the serialized JSON message.
 * \return 0 for success.\n
 *         1 for failure.
 */
int rpc_construct_response(json_t *response, char **data, size_t *data_len);

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
int32_t rpc_construct_and_send_message(struct connection *connection,
                                       json_t *message,
                                       rpc_response_handler success_handler,
                                       rpc_response_handler failure_handler,
                                       rpc_free_func free_func,
                                       rpc_request_context_t *customer_callback_ctx,
                                       write_func write_function);

/**
 * \brief Constructs and sends the response.
 *
 * \param connection The connection to write the data for.
 * \param response The json response to serialize.
 * \param free_func The internal free function to be called after success or failure of this function call.
 * \param customer_callback_ctx The user-supplied customer callback context data pointer that is passed to the
 *        free_func.
 * \return 0 if the response was successfully sent.\n
 *        -1 if the response couldn't be allocated.\n
 *        -2 if the response couldn't be sent.
 */
int32_t rpc_construct_and_send_response(struct connection *connection,
                                        json_t *response,
                                        rpc_free_func free_func,
                                        rpc_request_context_t *customer_callback_ctx,
                                        write_func write_function);

/**
 * \brief Handles the incoming raw json-rpc string from the connection.
 * \param data The byte data buffer of the received data.
 * \param len The length of the byte data buffer.
 * \param connection The connection to which the data belongs.
 * \param method_table The method array for JSONRPC API.
 * \param write_func The function to use for writing data back.
 * \param protocol_error The flag is set to true if the frame data cannot be parsed or response message cannot be
 *                       matched. Otherwise it is set to false.
 * \param mutex_acquired The flag telling wheter the `rpc_mutex` is already acquired.
 * \return 0 for success.\n
 *         1 for failure.
 */
int rpc_handle_message(const char *data,
                       size_t len,
                       struct connection *connection,
                       struct jsonrpc_method_entry_t *method_table,
                       write_func write_function,
                       bool *protocol_error,
                       bool mutex_acquired);

/**
 * \brief Destroys all messages that are waiting for processing.
 */
void rpc_destroy_messages();

/**
 * \brief Adds the `message_entry` to the RPC message entry list. It is used to match the request messages
 * to reponses. The `messsage_entry` is typically created by calling `rpc_construct_message`.
 *
 * \param message_entry The message to add to the list.
 */
void rpc_add_message_entry_to_list(void *message_entry);

/**
 * \brief Deallocates the `message_entry`. The client needs to deallocate it manually by calling this function if the
 * message cannot be sent.
 *
 * \param message_entry The message that is to be deallocated and which is typically created by calling
 * `rpc_construct_message`.
 */
void rpc_dealloc_message_entry(void *message_entry);

/**
 * \brief Handles the the requests which have been pending for too long by sending timeout response.
 *
 * \param max_response_time_ms The threshold duration until which we trigger the timeout response.
 */
void rpc_timeout_unresponded_messages(int32_t max_response_time_ms);

/**
 * \brief Should be called when the connection is disconnected.
 *        It handles the pending requests by sending the remote disconnected error response.
 * \param connection The connection which disconnected.
 */
void rpc_remote_disconnected(struct connection *connection);

/**
 * @}
 * Close EDGE_RPC Doxygen group definition
 */

#endif /* RPC_H_ */
