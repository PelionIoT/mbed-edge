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

#ifndef EDGE_CLIENT_REQUEST_CONTEXT_H_
#define EDGE_CLIENT_REQUEST_CONTEXT_H_

#include <stdint.h>
#include "common/constants.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Request context for the Edge client.
 */
typedef struct edgeclient_request_context edgeclient_request_context_t;

typedef enum {
    EDGECLIENT_VALUE_IN_TEXT,
    EDGECLIENT_VALUE_IN_BINARY,
} edgeclient_value_format_e;

/**
 * \brief Return values for Edge request context operations
 */
typedef enum edge_rc_status {
    EDGE_RC_STATUS_SUCCESS,                /* The operation succeeded */
    EDGE_RC_STATUS_CANNOT_ALLOCATE_MEMORY, /* A memory allocation failed */
    EDGE_RC_STATUS_INVALID_VALUE_FORMAT,   /* Invalid format received for value type. */
    EDGE_RC_STATUS_CANNOT_PARSE_URI,       /* The given uri cannot be parsed. */
    EDGE_RC_STATUS_INVALID_PARAMETERS      /* Given parameters were not correct. */
} edge_rc_status_e;

/**
 * \brief Handler to call when response is available for Edge clients initiated requets.
 * \param ctx Request context which was passed in the original request.
 */
typedef void (*edgeclient_response_handler)(edgeclient_request_context_t *ctx);

typedef struct edgeclient_request_context {
    char *device_id; /**< The device id. */
    uint16_t object_id; /**< The object id. */
    uint16_t object_instance_id; /**< The object instance id. */
    uint16_t resource_id; /**< The resource id. */
    Lwm2mResourceType resource_type; /**< The resource type. */
    uint8_t *value; /**< The pointer to bytes resulting from decoding text format value to the correct data type. This will be passed to protocol translator. */
    uint32_t value_len; /**< The size of the value buffer. */
    uint8_t *token; /**< This is used for saving the token given by cloud client. The response is sent back using this
                       token. */
    uint8_t token_len; /**< The size of the token. */
    uint8_t operation; /**< The operation done to the resource. */
    edgeclient_response_handler success_handler; /**< The success handler to call on success response */
    edgeclient_response_handler failure_handler; /**< The failure handler to call on failure response */
    void *connection; /**< The connection context */
    int16_t jsonrpc_error_code; /**< The request response error code. This is mapped to COAP error */
} edgeclient_request_context_t;

/**
 * \brief The request context deallocation function.
 * \param request_context The context to deallocate.
 */
void edgeclient_deallocate_request_context(edgeclient_request_context_t *request_context);

/**
 * \brief The request context allocation function.
 * \param uri The resource uri of the request.
 * \param value The value for performed action.
 *        On success the the value is freed. On failure the value is not freed.
 * \param value_len The amount of bytes in the value.
 * \param token The token for performed action.
 *        On success the the token is freed. On failure the token is not freed.
 * \param token_len The amount of bytes in the token.
 * \param value_format The format in which the value is. See ::edgeclient_value_format_e.
 * \param operation The performed operation
 *        #OPERATION_WRITE or #OPERATION_EXECUTE
 * \param resource_type Data type of the resource.
 * \param success_handler The handler function to call on success response.
 * \param failure_handler The handler function to call on failure response.
 * \param connection The supplied connection context if successul.
 * \param[out] status On success #EDGE_RC_STATUS_SUCCESS. Other error codes for failure.
 * \return On failure NULL is returned.
 *         On success the allocated context pointer is returned.
 */
edgeclient_request_context_t *edgeclient_allocate_request_context(const char *uri,
                                                                  uint8_t *value,
                                                                  uint32_t value_len,
                                                                  uint8_t *token,
                                                                  uint8_t token_len,
                                                                  edgeclient_value_format_e value_format,
                                                                  uint8_t operation,
                                                                  Lwm2mResourceType resource_type,
                                                                  edgeclient_response_handler success_handler,
                                                                  edgeclient_response_handler failure_handler,
                                                                  edge_rc_status_e *status,
                                                                  void *connection);

#ifdef __cplusplus
}
#endif

#endif // EDGE_CLIENT_REQUEST_CONTEXT_H_
