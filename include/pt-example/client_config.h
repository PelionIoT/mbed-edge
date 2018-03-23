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

#ifndef EDGE_CLIENT_CONFIG_H
#define EDGE_CLIENT_CONFIG_H

#include <stdbool.h>
#include "pt-client/pt_api.h"
#include "ns_list.h"

typedef struct pt_device_entry {
    ns_list_link_t link;
    pt_device_t *device;
} pt_device_entry_t;

typedef NS_LIST_HEAD(pt_device_entry_t, link) pt_device_list_t;

const char *client_config_get_cpu_thermal_zone_file_path();
const char *client_config_get_protocol_translator_name();
pt_device_t *client_config_create_reappearing_device(const char *device_id, const char *endpoint_postfix);
pt_device_list_t *client_config_create_device_list(const char *endpoint_postfix);
pt_device_t *client_config_create_cpu_temperature_device(const char *device_id, const char *endpoint_postfix);
void client_config_add_device_to_config(pt_device_list_t *device_list, pt_device_t *device);
void client_config_free();
bool client_config_parse(const char *filename);

#endif /* EDGE_CLIENT_CONFIG_H */
