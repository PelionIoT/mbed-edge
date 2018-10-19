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

#ifndef CLIENT_H_
#define CLIENT_H_

#include "pt-client/pt_api.h"

struct context;

/**
 * \brief Initializes the connection structure between Mbed Cloud Edge and the connected
 * protocol translator.
 * \param ctx The program context.
 * \param protocol_translator The protocol translator context.
 * \param pt_cbs The protocol translator user supplied callback functions.
 * \return The connection structure containing the connection-related data.
 */
struct connection* connection_init(struct context *ctx,
                                   client_data_t *client_data,
                                   const protocol_translator_callbacks_t *pt_cbs,
                                   void *userdata);
void connection_free(struct connection *connection);

/**
 * \brief Set the message id generation function.
 * \param generate_msg_id The function pointer or NULL. If NULL is given, a default implementation is selected.
 */
void pt_client_set_msg_id_generator(generate_msg_id generate_msg_id);

/**
 * \brief This function cleans used memory, e.g. unhandled requests.
 * It needs to be called before just before exiting the client application.
 *
 * */
void pt_client_final_cleanup();

#endif /* CLIENT_H_ */
