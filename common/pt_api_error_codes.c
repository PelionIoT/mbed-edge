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

#include <stddef.h>
#include "common/pt_api_error_codes.h"

struct error_message_entry_t {
    const pt_api_result_code_e code;
    const char* msg;
};

struct error_message_entry_t ERROR_MESSAGES[] =
        {{PT_API_INTERNAL_ERROR, "Protocol translator API internal error."},
         {PT_API_PROTOCOL_TRANSLATOR_NOT_REGISTERED, "Protocol translator not registered."},
         {PT_API_PROTOCOL_TRANSLATOR_ALREADY_REGISTERED, "Protocol translator already registered."},
         {PT_API_PROTOCOL_TRANSLATOR_NAME_RESERVED, "Protocol translator name reserved."},
         {PT_API_PROTOCOL_TRANSLATOR_CLIENT_WRITE_ERROR, "Protocol translator client write error."},
         {PT_API_REGISTERED_ENDPOINT_LIMIT_REACHED, "The maximum number of registered endpoints is already in use."},
         {PT_API_RESOURCE_NOT_FOUND, "Resource not found."},
         {PT_API_RESOURCE_NOT_READABLE, "Resource not readable."},
         {PT_API_RESOURCE_NOT_WRITABLE, "Resource not writable."},
         {PT_API_ILLEGAL_VALUE, "Illegal value."},
         {PT_API_INVALID_JSON_STRUCTURE, "Invalid json structure."},
         {PT_API_ENDPOINT_ALREADY_REGISTERED, "Cannot register endpoint, because it's already registered."},
         {PT_API_WRITE_TO_PROTOCOL_TRANSLATOR_FAILED, "Write request to protocol translator failed."},
         {PT_API_EDGE_CORE_SHUTTING_DOWN, "Edge Core is shutting down."},
         {PT_API_REQUEST_TIMEOUT, "Request timeout."},
         {PT_API_REMOTE_DISCONNECTED, "Remote disconnected."},
         {PT_API_CERTIFICATE_RENEWAL_BUSY, "Certificate renewal failed. Certificate enrollment client is busy."},
         {PT_API_CERTIFICATE_RENEWAL_ERROR, "Certificate renewal failed. Certificate enrollment client internal error."},
         {PT_API_CERTIFICATE_RENEWAL_INVALID_PARAMETERS, "Certificate renewal failed. Invalid parameters."},
         {PT_API_CERTIFICATE_RENEWAL_MEMORY_ALLOCATION_FAILURE, "Certificate renewal failed. A memory allocation failed."},
         {PT_API_UNKNOWN_ERROR, NULL}};

const char *pt_api_get_error_message(pt_api_result_code_e code)
{
    struct error_message_entry_t *entry;

    for (entry = ERROR_MESSAGES; entry->code != PT_API_UNKNOWN_ERROR; entry++) {
        if (code == entry->code) // find message
            break;
    }

    if (entry->code != PT_API_UNKNOWN_ERROR) {
        return entry->msg;
    }
    return "Unknown error code.";
}

