/*
 * Copyright (c) 2015 ARM Limited. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 * Licensed under the Apache License, Version 2.0 (the License); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <string.h>
#include <stdint.h>
#include "edge-client/edge_client.h"
#include "CppUTestExt/MockSupport.h"

extern "C" {
    void edgeserver_exit_event_loop()
    {
        mock().actualCall("edgeserver_exit_event_loop");
    }

    void edgeserver_graceful_shutdown()
    {
        mock().actualCall("edgeserver_graceful_shutdown");
    }

    bool edgeserver_remove_protocol_translator_nodes()
    {
        return mock().actualCall("edgeserver_remove_protocol_translator_nodes")
                .returnBoolValue();
    }
    void edgeserver_resource_async_request(edgeclient_request_context_t *request_ctx)
    {
        mock().actualCall("edgeserver_resource_async_request")
                .withPointerParameter("request_ctx", (void *) request_ctx);
    }

    bool edgeserver_execute_rfs_customer_code(edgeclient_request_context_t *request_ctx) {
        return mock().actualCall("edgeserver_execute_rfs_customer_code").returnBoolValue();
    }

    void edgeserver_rfs_customer_code_succeeded()
    {
        mock().actualCall("edgeserver_rfs_customer_code_succeeded");
    }

    struct event_base *edge_server_get_base()
    {
        return (struct event_base *) mock().actualCall("edge_server_get_base")
                .returnPointerValue();
    }

}
