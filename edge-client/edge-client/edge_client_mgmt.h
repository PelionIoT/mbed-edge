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

#ifndef EDGE_CLIENT_MGMT_H_
#define EDGE_CLIENT_MGMT_H_

#include "ns_list.h"
#include "common/constants.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct edge_device_resource_entry_s {
    ns_list_link_t link;
    char *uri;
    Lwm2mResourceType type;
    uint8_t operation;
} edge_device_resource_entry_t;

typedef NS_LIST_HEAD(edge_device_resource_entry_t, link) edge_device_resource_list_t;

typedef struct edge_device_entry_s {
    ns_list_link_t link;
    char *name;
    edge_device_resource_list_t *resources;
} edge_device_entry_t;

typedef NS_LIST_HEAD(edge_device_entry_t, link) edge_device_list_t;

void edgeclient_destroy_device_list(edge_device_list_t *devices);
edge_device_list_t *edgeclient_devices();

#ifdef __cplusplus
}
#endif

#endif // EDGE_CLIENT_MGMT_H_
