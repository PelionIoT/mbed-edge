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

#include "edge-rpc/rpc_timeout_api.h"
#include <event2/event.h>
#include <sys/time.h>
#include <stdlib.h>
#include "edge-rpc/rpc.h"
#include "common/test_support.h"

#include "mbed-trace/mbed_trace.h"
#define TRACE_GROUP "rpctimeout"

struct rpc_request_timeout_hander {
    struct event *ev;
    int32_t max_response_time_ms;
};

EDGE_LOCAL void handle_timed_out_requests(evutil_socket_t fd, short what, void *arg)
{
    rpc_request_timeout_hander_t *handler = (rpc_request_timeout_hander_t *) arg;
    rpc_timeout_unresponded_messages(handler->max_response_time_ms);
}

rpc_request_timeout_hander_t *rpc_request_timeout_api_start(struct event_base *base,
                                                            int32_t check_period_in_ms,
                                                            int32_t max_response_time_ms)
{
    rpc_request_timeout_hander_t *handler = calloc(1, sizeof(rpc_request_timeout_hander_t));
    if (handler) {
        struct timeval duration = {0};
        duration.tv_sec = check_period_in_ms / 1000;
        duration.tv_usec = (check_period_in_ms % 1000) * 1000;
        struct event *ev;
        ev = event_new(base, -1, EV_PERSIST, handle_timed_out_requests, handler);
        if (NULL == ev) {
            tr_err("Failed to allocate event in rpc_request_timeout_api_start");
            free(handler);
            return NULL;
        }
        int ret_code = event_add(ev, &duration);
        if (0 != ret_code) {
            tr_err("Failed to start periodic timer in rpc_request_timeout_api_start");
            event_free(ev);
            free(handler);
            return NULL;
        }
        handler->max_response_time_ms = max_response_time_ms;
        handler->ev = ev;
    }
    return handler;
}

void rpc_request_timeout_api_stop(rpc_request_timeout_hander_t *handler)
{
    if (handler) {
        int ret_code = event_del(handler->ev);
        if (0 != ret_code) {
            tr_err("rpc_request_timeout_api_stop: event del returned %d", ret_code);
        }
        event_free(handler->ev);
        free(handler);
    }
}

