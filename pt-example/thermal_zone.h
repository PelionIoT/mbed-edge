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

#ifndef EDGE_THERMAL_ZONE_H
#define EDGE_THERMAL_ZONE_H

/**
 * \brief Check if CPU thermal zone is supported
 * \return If thermal zone for CPU is not supported 0 is returned.
 * If thermal zone for CPU is supported 1 is returned.
 */
int tzone_has_cpu_thermal_zone();

/**
 * \brief Reads and returns the current temperature of the CPU thermal zone.
 * \return The temperature as float, degrees are in Celsius.
 */
float tzone_read_cpu_temperature();

/**
 * Free the resources allocated by thermal zone module.
 */
void tzone_free();

#endif /* EDGE_THERMAL_ZONE_H */
