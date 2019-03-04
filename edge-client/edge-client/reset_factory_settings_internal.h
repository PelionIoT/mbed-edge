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

#ifndef RESET_FACTORY_SETTINGS_INTERNAL_H
#define RESET_FACTORY_SETTINGS_INTERNAL_H
#include <event2/event.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct x_rfs_thread_param {
    edgeclient_request_context_t *ctx;
    pthread_t *thread;
} rfs_thread_param_t;

typedef struct x_rfs_thread_result {
    pthread_t *thread;
    bool customer_rfs_succeeded;
    edgeclient_request_context_t *request_ctx;
} rfs_thread_result_t;

typedef struct x_rfs_request_message {
    edgeclient_request_context_t *request_ctx;
} rfs_request_message_t;

EDGE_LOCAL void rfs_reset_factory_settings_request_cb(void *arg);
EDGE_LOCAL void rfs_reset_factory_settings_response_cb(void *arg);
#ifdef __cplusplus
}
#endif

#endif
