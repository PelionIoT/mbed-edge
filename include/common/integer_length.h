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

#ifndef EDGE_INTEGER_LENGTH_H
#define EDGE_INTEGER_LENGTH_H

#include <stdint.h>

/**
 * \defgroup EDGE_INTEGER_LENGTH_LIB Integer length calculator
 * @{
 */

/** \file integer_length.h
 * \brief Edge common integer handling functions.
 */

/**
 * \brief Return the length of the integer in characters.
 * This function calculates the needed space of characters to represent
 * the integer argument.
 *
 * \param value The value to calculate the length as a characters.
 * \return The length as characters.
 */
uint16_t edge_int_length(uint32_t value);

/**
 * \brief Convert the string to uin16_t.
 *
 * \param str String to convert. String must be NUL-terminated.
 * \param result The pointer where to store the result.
 * \return 0 if conversion succeeded.\n
           1 if an error occured when converting str to uint16_t.
 */
int edge_str_to_uint16_t(const char *str, uint16_t *result);

/**
 * @}
 * close EDGE_INTEGER_LENGTH_LIB Doxygen group definition
 */

#endif /* EDGE_INTEGER_LENGTH_GENERATOR_H */
