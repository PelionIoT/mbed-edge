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

#ifndef EDGE_TIME_H
#define EDGE_TIME_H

#include <stdint.h>
#include <stdbool.h>

/**
 * \defgroup EDGE_TIME Edge time API.
 * @{
 */

/** \file edge_time.h
 * \brief Edge time API
 *
 * Utility functions for getting time.
 */

/**
 * \brief Get current milliseconds.
 * Uses CLOCK_MONOTONIC as source from POSIX.1-2001, POSIX.1-2008, SUSv2 compliant system.
 * If _POSIX_MONOTONIC_CLOCK is not defined the function returns 0.
 * \return current milliseconds as uint64_t or 0 if clock source is not available.
 */
uint64_t edgetime_get_monotonic_in_ms();

/**
 * \brief Get the real time in seconds and nanoseconds.
 * Uses CLOCK_REAL as source.
 * \return true  if the system call succeeded.
 *         false if the system call failed and sets seconds and ns to 0.
 */
bool edgetime_get_real_in_ns(uint64_t *seconds, uint64_t *ns);

/**
 * @}
 * Close EDGE_TIME Doxygen group definition
 */

#endif
