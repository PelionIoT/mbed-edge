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

#ifndef RPC_TIMEOUT_API_H
#define RPC_TIMEOUT_API_H

#include <stddef.h>
#include <event2/event.h>

struct rpc_request_timeout_hander;
typedef struct rpc_request_timeout_hander rpc_request_timeout_hander_t;

/**
 * \brief Sets up a periodic timer to handle unresponded JSON RPC requests. The requests that are pending too long
 *        are given a time-out response specified by `max_response_time_ms` parameter.
 *        The timeout response needs to be sent so that badly behaving clients can't so easily harm the performance of
 *        the server that made the requests.
 * \param base Pointer to libevent base structure.
 * \param check_period_in_ms Specifies the interval how often we look for timed out requests.
 * \param max_response_time_ms The maximum time given to respond to the JSON RPC request in milliseconds.
 * \return Pointer the timeout event handler which is needed in cleanup.
 */
rpc_request_timeout_hander_t *rpc_request_timeout_api_start(struct event_base *base,
                                                            int32_t check_period_in_ms,
                                                            int32_t max_response_time_ms);

/**
 * \brief Stops the periodic timer to send timeout responses. This should be called before stopping libevent.
 * \param handler Pointer to timeout event handler created by `rpc_request_timeout_api_start`.
 */
void rpc_request_timeout_api_stop(rpc_request_timeout_hander_t *handler);

#ifdef BUILD_TYPE_TEST
void handle_timed_out_requests(evutil_socket_t fd, short what, void *arg);
#endif

#endif
