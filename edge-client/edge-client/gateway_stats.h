/*
 * ----------------------------------------------------------------------------
 * Copyright 2021 ARM Ltd.
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

#ifndef _GATEWAY_STATS_H_
#define _GATEWAY_STATS_H_

/**
 * \ingroup GATEWAY_STATS_RESOURCES Gateway Statistics API
 * @{
 */

/**
 * \file gateway_stats.h
 * \brief Definition Gateway Statistics Resources internal API (internal).
 */

/**
 * \brief Adds the gateway statistics resources
 */
void gsr_add_gateway_stats_resources();

/**
 * \brief Single-shot function for updating gateway stats
 */
void gsr_update_gateway_stats_resources(void *arg);

#endif /* _GATEWAY_STATS_H_ */
