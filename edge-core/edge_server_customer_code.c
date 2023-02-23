/*
 * ----------------------------------------------------------------------------
 * Copyright 2018 ARM Ltd.
 * Copyright (c) 2023 Izuma Networks
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

#include <stdlib.h>
#include "edge-client/edge_client.h"
#include "mbed-trace/mbed_trace.h"
#include "edge-core/edge_server_customer_code.h"
#define TRACE_GROUP "escstmr"

bool edgeserver_execute_rfs_customer_code(edgeclient_request_context_t *request_ctx)
{
    if (request_ctx) {
        tr_info("edgeserver_execute_rfs_customer_code %d/%d/%d",
                request_ctx->object_id,
                request_ctx->object_instance_id,
                request_ctx->resource_id);
    } else {
        tr_info("edgeserver_execute_rfs_customer_code (local)");
    }
    // Snap-related addition
    // Execute a script to do factory reset tasks, such as clearing customer logs.
    int rc = system("edge-core-factory-reset");

    if (rc) {
        tr_warn("edge-core-factory-reset exited with non-success return code %d", rc);
        return false;
    }
    return true;
}
