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

#ifndef CLIENT_TYPE_H
#define CLIENT_TYPE_H

#include <stdbool.h>
#include "ns_list.h"

enum client_type {
    PT,
    MGMT
};

typedef struct string_list_entry {
    char *string;
    ns_list_link_t link;
} string_list_entry_t;

typedef NS_LIST_HEAD(string_list_entry_t, link) string_list_t;

struct client_data;

typedef void (*pre_destroy_client_data)(struct client_data *client_data);

typedef struct client_data {
    char *name;
    bool registered;
    int id;
    void *method_table;
    string_list_t certificate_list;
    pre_destroy_client_data _pre_destroy_client_data;
} client_data_t;

/*
 * \brief Create a new client
 */
client_data_t *edge_core_create_client(enum client_type client_type);
void edge_core_client_data_destroy(client_data_t **client_data);

#endif // CLIENT_TYPE_H
