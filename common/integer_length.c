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

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "common/integer_length.h"

uint16_t edge_int_length(uint32_t value)
{
    uint16_t length = 1;
    while (value > 9) {
        length++;
        value /= 10;
    }
    return length;
}

int edge_str_to_uint16_t(const char *str, uint16_t *result)
{
    if (!str || strlen(str) == 0) {
        return 1;
    }
    uint16_t len = strlen(str);
    for (int i = 0; i < len; i++) {
        if (str[i] < '0' || str[i] > '9') {
            return 1;
        }
    }
    *result = atoi(str);
    return 0;
}
