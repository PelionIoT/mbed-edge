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

#define _POSIX_C_SOURCE 200809L
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include "common/edge_time.h"
#include <time.h>

uint64_t edgetime_get_monotonic_in_ms()
{
#ifdef _POSIX_MONOTONIC_CLOCK
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
        return (uint64_t)(ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
    } else {
        return 0;
    }
#else
    return 0;
#endif
}

bool edgetime_get_real_in_ns(uint64_t *seconds, uint64_t *ns)
{
    struct timespec spec;
    if (0 == clock_gettime(CLOCK_REALTIME, &spec)) {
        *ns = spec.tv_nsec;
        *seconds = spec.tv_sec;
        return true;
    } else {
        *ns = 0;
        *seconds = 0;
    }
    return false;
}

