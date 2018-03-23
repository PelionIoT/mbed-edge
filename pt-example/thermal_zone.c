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

#include <dirent.h>
#include <float.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "pt-example/thermal_zone.h"
#include "pt-example/read_file.h"
#include "mbed-trace/mbed_trace.h"

#define TRACE_GROUP            "tzone"
#define THERMAL_ZONE_CPU_TYPE  "x86_pkg_temp"
#define THERMAL_ZONE_CLASS_DIR "/sys/class/thermal"
#define THERMAL_ZONE_PREFIX    "thermal_zone"

static char* cpu_thermal_zone_temp_file = NULL;

const char *tzone_get_cpu_thermal_zone_file_path()
{
    if (!cpu_thermal_zone_temp_file) {
        DIR *d;
        struct dirent *dir;
        d = opendir(THERMAL_ZONE_CLASS_DIR);
        if (d) {
            while ((dir = readdir(d)) != NULL) {
                if (strncmp(THERMAL_ZONE_PREFIX, dir->d_name, strlen(THERMAL_ZONE_PREFIX)) == 0) {
                    char *type_file = malloc(strlen(THERMAL_ZONE_CLASS_DIR) + strlen(dir->d_name)
                                             + /* two slashes+ NULL */ 3 + strlen("type"));
                    if (type_file != NULL) {
                        sprintf(type_file, "%s/%s/type", THERMAL_ZONE_CLASS_DIR, dir->d_name);
                        char *type = NULL;
                        size_t read;
                        if (read_file_content(type_file, &type, &read) != 0 || read == 0) {
                            tr_err("Could not read the thermal zone type.");
                        }
                        free(type_file);
                        if(strncmp(THERMAL_ZONE_CPU_TYPE, type, strlen(THERMAL_ZONE_CPU_TYPE)) == 0) {
                            if (cpu_thermal_zone_temp_file != NULL) {
                                free(cpu_thermal_zone_temp_file);
                            }
                            cpu_thermal_zone_temp_file = malloc(strlen(THERMAL_ZONE_CLASS_DIR) + strlen(dir->d_name)
                                                 + /* two slashes + NULL */ 3 + strlen("temp"));
                            sprintf(cpu_thermal_zone_temp_file, "%s/%s/temp", THERMAL_ZONE_CLASS_DIR, dir->d_name);
                        }
                        free(type);
                    }
                    else {
                        tr_err("Could not allocate memory for type_file.");
                    }
                }
            }
        }
        closedir(d);
    }
    return cpu_thermal_zone_temp_file;
}

int tzone_has_cpu_thermal_zone()
{
    const char* path = tzone_get_cpu_thermal_zone_file_path();
    if (!path || access(tzone_get_cpu_thermal_zone_file_path(), F_OK) != -1) {
        return 1;
    } else {
        tr_info("Could not access CPU thermal zone, either not supported or permission denied.");
        return 0;
    }
}

float tzone_read_cpu_temperature()
{
    float temperature = 0;
    if (tzone_has_cpu_thermal_zone() == 1) {
        /* Read the temperature from file, in Linux the temperature is in millis */
        char *buffer = NULL;
        size_t read;
        if (read_file_content(tzone_get_cpu_thermal_zone_file_path(), &buffer, &read) != 0
            || read == 0) {
            float r = (float) rand() / (float) RAND_MAX;
            float rand_temp = 20.0 + (r * 80.0);
            if (buffer != NULL) {
                free(buffer);
            }

            tr_err("Could not read bytes from thermal zone temperature file, returning random temperature between 20 "
                   "and 100 - %f.",
                   rand_temp);
            return rand_temp;
        }
        temperature = atof(buffer) / 1000;
        tr_debug("Read temperature value: %s | Converted to float %f.", buffer, temperature);
        if (buffer != NULL) {
            free(buffer);
        }

    } else {
        tr_warn("Thermal zone for CPU not available.");
    }
    return temperature;
}

void tzone_free()
{
    free(cpu_thermal_zone_temp_file);
    cpu_thermal_zone_temp_file = NULL;
}
