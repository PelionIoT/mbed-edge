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

#ifndef PT_API_ERROR_CODES_H_
#define PT_API_ERROR_CODES_H_

/**
 * \defgroup PT_API_ERROR_CODES Edge and protocol translator common definitions.
 * @{
 */

/**
 * \file pt_api_error_codes.h
 * \brief Edge service error codes.
 *
 * Note: The error codes are extending JSON RPC error codes. They should not overlap with them, see:
 * http://www.jsonrpc.org/specification and lib/jsonrpc/jsonrpc.h.
 */

typedef enum {

    /*
     * Generic error codes
     */

    /**
     * \brief Operation succeeded.
     */
    PT_API_SUCCESS = 0,

    /**
     * \brief Unknown PT API error
     */
    PT_API_UNKNOWN_ERROR = -1,

    /*
     * Error codes related to server state
     */

    /**
     * \brief An internal error code.
     */
    PT_API_INTERNAL_ERROR = -30000,

    /**
     * \brief The protocol translator is not registered.
     */
    PT_API_PROTOCOL_TRANSLATOR_NOT_REGISTERED = -30001,

    /**
     * \brief The protocol translator is already registered.
     */
    PT_API_PROTOCOL_TRANSLATOR_ALREADY_REGISTERED = -30002,

    /**
     * \brief The given protocol translator name is already registered.
     */
    PT_API_PROTOCOL_TRANSLATOR_NAME_RESERVED = -30003,

    /**
     * \brief Cannot add new endpoint, because the maximum number of registered endpoints is already in use.
     */
    PT_API_REGISTERED_ENDPOINT_LIMIT_REACHED = -30004,

    /**
     * \brief Cannot register the endpoint, because it is already registered.
     */
    PT_API_ENDPOINT_ALREADY_REGISTERED = -30005,

    /**
     * \brief The Edge Core is shutting down.
     */
    PT_API_EDGE_CORE_SHUTTING_DOWN = -30006,

    /**
     * \brief The request timed out.
     */
    PT_API_REQUEST_TIMEOUT = -30007,

    /**
     * \brief The request timed out.
     */
    PT_API_REMOTE_DISCONNECTED = -30008,

    /*
     * Error codes related to client state.
     */

    /**
     * \brief The protocol translator client write error.
     */
    PT_API_PROTOCOL_TRANSLATOR_CLIENT_WRITE_ERROR = -30100,

    /**
     * \brief An illegal value was given to write
     */
    PT_API_ILLEGAL_VALUE = -30101,

    /**
     * \brief The given resource was not found.
     */
    PT_API_RESOURCE_NOT_FOUND = -30102,

    /**
     * \brief the JSON structure is not according to specification.
     */
    PT_API_INVALID_JSON_STRUCTURE = -30103,

    /**
     * \brief The resource was not readable.
     */
    PT_API_RESOURCE_NOT_READABLE = -30104,

    /**
     * \brief The resource was not writable.
     */
    PT_API_RESOURCE_NOT_WRITABLE = -30105,

    /**
     * \brief Write to protocol translator failed.
     */
    PT_API_WRITE_TO_PROTOCOL_TRANSLATOR_FAILED = -30106,

    /**
     * \brief Certificate renewal failed because one is already in progress.
     */
    PT_API_CERTIFICATE_RENEWAL_BUSY = -30107,

    /**
     * \brief Certificate renewal failed to internal error.
     */
    PT_API_CERTIFICATE_RENEWAL_ERROR = -30108,

    /**
     * \brief Certificate renewal failed to invalid parameters.
     */
    PT_API_CERTIFICATE_RENEWAL_INVALID_PARAMETERS = -30109,

    /**
     * \brief Certificate renewal failed because a  memory allocation failed.
     */
    PT_API_CERTIFICATE_RENEWAL_MEMORY_ALLOCATION_FAILURE = -30110

} pt_api_result_code_e;

/**
 * \brief Get the human-readable error message for the error code.
 * \return The error message.
 */
const char *pt_api_get_error_message(pt_api_result_code_e code);

/**
 * @}
 * Close PT_API_ERROR_CODES Doxygen ingroup definition
 */

#endif /* PT_API_ERROR_CODES_H_ */
