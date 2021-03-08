/*
 * ----------------------------------------------------------------------------
 * Copyright 2021 ARM Ltd.
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

#define TRACE_GROUP "edgegsr"

#include "edge-client/gateway_stats.h"
#include "edge-client/edge_client.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define GATEWAY_STATS_OBJ_ID 3

// run shell cmd and copy results to out_buffer
// return 0 for success or -1 on failure
static int sys_exec(const char *cmd, char *out_buffer, size_t out_buffer_size)
{
    FILE *fp;
    char buffer[128];
    fp = popen(cmd, "r");
    if (fp == NULL)
        return -1;
    size_t rem = out_buffer_size;
    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        strncat(out_buffer, buffer, rem);
        rem -= strlen(buffer);
        if (rem < 0) {
            rem = 0;
        }
    }
    pclose(fp);
    return 0;
}

static pt_api_result_code_e gsr_create_resource(const uint16_t object_id,
                                                const uint16_t object_instance_id,
                                                const uint16_t resource_id,
                                                const char *resource_name,
                                                Lwm2mResourceType resource_type,
                                                int ops,
                                                const uint8_t *value,
                                                const uint32_t value_length,
                                                void *ctx)
{
    if (!edgeclient_create_resource_structure(NULL,
                                              object_id,
                                              object_instance_id,
                                              resource_id,
                                              resource_name,
                                              resource_type,
                                              ops,
                                              ctx)) {
        tr_error("gsr: could not create resource structure: %u/%u/%u", object_id, object_instance_id, resource_id);
        return PT_API_INTERNAL_ERROR;
    }

    return edgeclient_set_resource_value_native(NULL, object_id, object_instance_id, resource_id, value, value_length);
}

// updates gateway statistics resources
void gsr_update_gateway_stats_resources(void *arg)
{
    return;
}

// add gateway statistics
void gsr_add_gateway_stats_resources()
{
    return;
}
