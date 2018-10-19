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

#ifndef EDGE_CLIENT_FORMAT_VALUES_H_
#define EDGE_CLIENT_FORMAT_VALUES_H_

#include <arpa/inet.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "common/constants.h"
#include "common_functions.h"
#include "common/test_support.h"

/*
 * \brief Decode a buffer containing string representation of resource value into a buffer
 *        containing the binary representation in correct type and network byte order.
 * \param resource_type Type of the resource, ie. the contents of value buffer will be
 *                      interpreted as this type.
 * \param value Pointer to string buffer containing the value. MUST be null terminated.
 * \param value_length Length of value buffer
 * \param buffer Output parameter, pointer to a char pointer, if value is successfully
 *               decoded this will point to a dynamically allocated buffer containing the
 *               binary representation of value in network byte order. Null if value could
 *               not be decoded.
 * \return Size of the output buffer if value was successfully decoded, 0 otherwise.
 */
size_t text_format_to_value(Lwm2mResourceType resource_type,
                            const uint8_t* value,
                            const uint32_t value_length,
                            uint8_t** buffer);

/*
 * \brief Encode a buffer containing binary representation of resource value in network byte
 *        order into a buffer containing the textual representation as interpreted based on
 *        the resource type.
 * \param resource_type Type of the resource, ie. the contents of value buffer will be
 *                      encoded into this type.
 * \param value Pointer to binary buffer containing the value.
 * \param value_length Length of value buffer
 * \param buffer Output parameter, pointer to a char pointer, if value is successfully
 *               encoded this will point to a dynamically allocated string buffer containing
 *               the textual representation of value in network byte order. Null if value
 *               could not be decoded.
 *               If the pointer is NULL, we don't allocate the buffer but just return the
 *               size that would be allocated excluding the NULL terminator.
 * \return Size of the output buffer if value was successfully decoded, 0 otherwise.
 */
size_t value_to_text_format(Lwm2mResourceType resource_type,
                            const uint8_t* value,
                            const uint32_t value_length,
                            char** buffer);

size_t integer_to_text_format(int32_t value, char *buffer, size_t buffer_len);
size_t long_integer_to_text_format(int64_t value, char *buffer, size_t buffer_len);
size_t float_to_text_format(float value, char *buffer, size_t buffer_len);
size_t double_to_text_format(double value, char *buffer, size_t buffer_len);
size_t bool_to_text_format(bool value, char *buffer, size_t buffer_len);
void convert_to_int32_t(const uint8_t *value, const size_t value_length, int32_t *number);
void convert_to_int64_t(const uint8_t *value, const size_t value_length, int64_t *number);
void convert_to_float(const uint8_t *value, const size_t value_length, float *number);
void convert_to_double(const uint8_t *value, const size_t value_length, double *number);

#endif //  EDGE_CLIENT_FORMAT_VALUES_H_
