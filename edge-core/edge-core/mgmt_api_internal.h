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

#ifndef MGMT_API_INTERNAL_H
#define MGMT_API_INTERNAL_H

#include "edge-rpc/rpc.h"

int devices(json_t *request, json_t *json_params, json_t **result, void *userdata);
int read_resource(json_t *request, json_t *json_params, json_t **result, void *userdata);
int write_resource(json_t *request, json_t *json_params, json_t **result, void *userdata);

extern struct jsonrpc_method_entry_t mgmt_api_method_table[];

#ifdef BUILD_TYPE_TEST
struct edgeclient_request_context;
void mgmt_api_write_success(struct edgeclient_request_context *ctx);
void mgmt_api_write_failure(struct edgeclient_request_context *ctx);
#endif

#endif // MGMT_API_INTERNAL_H
