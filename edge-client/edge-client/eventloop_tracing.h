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

#ifndef EVENTLOOP_TRACING_H_
#define EVENTLOOP_TRACING_H_

#ifdef EDGE_EVENTLOOP_STATS_TRACING

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

void eventloop_stats_init();

#ifdef __cplusplus
}
#endif // __cplusplus

#else // EDGE_EVENTLOOP_STATS_TRACING

// No eventloop tracing so define the empty init function
#define eventloop_stats_init(...) ((void)0)

#endif // EDGE_EVENTLOOP_STATS_TRACING

#endif // EVENTLOP_TRACING_H_
