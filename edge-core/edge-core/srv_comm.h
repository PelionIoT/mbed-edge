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

#ifndef SRV_COMM_H_
#define SRV_COMM_H_

#include "edge-core/protocol_api_internal.h"

struct connection;

int edge_core_write_data_frame_websocket(struct connection *connection, char *data, size_t len);
void edge_core_process_data_frame_websocket(struct connection *connection,
                                            bool *protocol_error,
                                            size_t len,
                                            const char *data);
bool close_connection(struct connection *connection);
void close_connection_trigger(struct connection *connection);
int edge_core_count_send_queue_websocket(struct connection *connection);
void connection_destroy(struct connection **connection);

#endif /* SRV_COMM_H_ */

