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

#ifndef EDGE_DEFAULT_MESSAGE_ID_GENERATOR_H
#define EDGE_DEFAULT_MESSAGE_ID_GENERATOR_H

/**
 * \defgroup EDGE_DEFAULT_MESSAGE_ID_GENERATOR_LIB Default message id generator library
 * @{
 */

/**
 * \file default_message_id_generator.h
 * \brief Default message ID generator for JSON-RPC messages.
 */

/**
 * \brief A prototype of the ID generation function.
 *
 * The function must provide unique and non-clashing IDs for the session.
 *
 * \return A unique message ID.
 */
typedef char *(*generate_msg_id)();

/**
 * \brief Default message generation function.
 *
 * This function implements a default message generator function. The prototype definition
 * of the function is `::generate_msg_id`.
 *
 * \return Numeric ascending message IDs are generated and returned as a character array.\n
 *         The character array is NULL terminated.\n
 *         If the allocation fails, NULL is returned.
 */
char *edge_default_generate_msg_id();

/**
 * @}
 * close EDGE_DEFAULT_MESSAGE_ID_GENERATOR_LIB Doxygen group definition
 */

#endif /* EDGE_DEFAULT_MESSAGE_ID_GENERATOR_H */
