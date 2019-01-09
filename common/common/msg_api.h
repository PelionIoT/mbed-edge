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

#ifndef MSG_API_H
#define MSG_API_H

#include <stddef.h>
#include <event2/event.h>
#include <stdbool.h>

/**
 * \brief Type definition for MSG API call back function.
 */
typedef void (*event_loop_callback_t)(void *data);

/**
 * \brief Sends a message to libevent event loop
 * \param base Pointer to libevent base structure.
 * \param message The message to send
 * \param callback The callback function which will receive the message.
 * \return true if the message was successfully sent.
 *         false if the message couldn't be sent.
 */
bool msg_api_send_message(struct event_base *base, void *data, event_loop_callback_t callback);

/**
 * \brief Sends a message to libevent event loop
 * \param base Pointer to libevent base structure.
 * \param message The message to send
 * \param callback The callback function which will receive the message.
 * \param timeout_in_ms Duration for triggering this message.
 * \return true if the message was successfully triggered.
 *         false if the message couldn't be triggered.
 */
bool msg_api_send_message_after_timeout_in_ms(struct event_base *base,
                                              void *data,
                                              event_loop_callback_t callback,
                                              int32_t timeout_in_ms);

#endif
