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
#ifdef _WIN32
#include <windows.h>
#include "pal.h"
#else
#include <unistd.h>
#endif
#include "common/edge_time.h"
#include <time.h>

uint64_t edgetime_get_monotonic_in_ms()
{
#ifdef _WIN32
    return pal_osKernelSysMilliSecTick(pal_osKernelSysTick());
#elif defined(_POSIX_MONOTONIC_CLOCK)
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
#ifdef _WIN32
    FILETIME time;
    ULARGE_INTEGER ticks;
    GetSystemTimePreciseAsFileTime(&time);
    ticks.LowPart = time.dwLowDateTime;
    ticks.HighPart = time.dwHighDateTime;
    /* FILETIME counts 100 ns intervals from 1601; Edge uses the Unix epoch. */
    uint64_t unix_ticks = ticks.QuadPart - UINT64_C(116444736000000000);
    *seconds = unix_ticks / UINT64_C(10000000);
    *ns = (unix_ticks % UINT64_C(10000000)) * 100;
    return true;
#else
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
#endif
}

