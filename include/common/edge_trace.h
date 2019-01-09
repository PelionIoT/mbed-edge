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
#ifndef EDGE_TRACE_API_H
#define EDGE_TRACE_API_H

#include "common/edge_mutex.h"

/**
 * \defgroup EDGE_TRACE Edge trace API.
 * @{
 */

/** \file edge_trace.h
 * \brief Edge trace API
 *
 * Utility functions for the Edge tracing functionality.
 */

/**
 * \brief The function may be used to initialize the Edge Trace API.
 * \param color_mode Set to true if ANSI color coded logging is needed. By setting false the plain text log is written.
 */
void edge_trace_init(int color_mode);

/**
 * \brief The function destroys the Edge Trace API and frees the related resources.
 */
void edge_trace_destroy();

#ifdef BUILD_TYPE_TEST
/**
 * \brief The static char buffer used for storing the timestamp prefix for the mbed-trace logger.
 */
extern char *timestamp_prefix;

/**
 * Mutex needed for serializing traces from different threads.
 */
extern edge_mutex_t trace_mutex;

/**
 * \brief The function to create timestamp prefixes for mbed-trace.
 *
 * \param size The length of the message body.
 * \return A pointer to timestamp prefix string.
 */
char *edge_trace_prefix(size_t size);
#endif

/**
 * @}
 * Close EDGE_TRACE Doxygen group definition
 */

#endif
