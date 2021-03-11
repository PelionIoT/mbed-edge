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

#define TRACE_GROUP "edgegsr"

#include "edge-client/gateway_stats.h"
#include "edge-client/edge_client.h"
#include "mbed-trace/mbed_trace.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define GATEWAY_STATS_OBJ_ID 3

#define GATEWAY_STATS_CPU_TEMP_RES_ID 3303
#define GATEWAY_STATS_CPU_PCT_RES_ID 3320
#define GATEWAY_STATS_RAM_FREE_RES_ID 3321
#define GATEWAY_STATS_RAM_TOTAL_RES_ID 3322
#define GATEWAY_STATS_DISK_FREE_RES_ID 3323
#define GATEWAY_STATS_DISK_TOTAL_RES_ID 3324

/**
 * \struct cpu_info
 * \brief a sample of cpu info from /proc/stat used by get_cpuu()
 */
struct cpu_info
{
    // raw data
    char cpu[20];

    // various cpu usage types from linux
    unsigned long long  user;
    unsigned long long  nice;
    unsigned long long  system;
    unsigned long long  idle;
    unsigned long long  io_wait;
    unsigned long long  irq;
    unsigned long long  soft_irq;
    unsigned long long  steal;
    unsigned long long  guest;
    unsigned long long  guest_nice;

    // combined stats for computing total cpu % with prev
    int all_idle;  // idle+iowate
    int non_idle;  // user + nice + system + irq + softirq + steal
    int total;     // all_idle + non_idle
};

// run shell cmd and copy results to out_buffer
// return 0 for success or -1 on failure
static int sys_exec(const char *cmd, char *out_buffer, size_t out_buffer_size)
{
    FILE *fp;
    char buffer[128];
    fp = popen(cmd, "r");
    if (fp == NULL)
        return -1;
    size_t rem = out_buffer_size;
    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        strncat(out_buffer, buffer, rem);
        rem -= strlen(buffer);
        if (rem < 0) {
            rem = 0;
        }
    }
    pclose(fp);
    return 0;
}

// run a shell command with the return result expected to
// be an unsigned integer value
static int64_t int_exec(const char* cmd)
{
    char result[256];
    memset(result, 0, sizeof(result));

    int ret = sys_exec(cmd, result, sizeof(result));
    if (ret == -1)
        strcpy(result, "0");

    return strtoll(result, (char **)NULL, 10);
}

static pt_api_result_code_e gsr_create_resource(const uint16_t object_id,
                                                const uint16_t object_instance_id,
                                                const uint16_t resource_id,
                                                const char *resource_name,
                                                Lwm2mResourceType resource_type,
                                                int ops,
                                                const uint8_t *value,
                                                const uint32_t value_length,
                                                void *ctx)
{
    if (!edgeclient_create_resource_structure(NULL,
                                              object_id,
                                              object_instance_id,
                                              resource_id,
                                              resource_name,
                                              resource_type,
                                              ops,
                                              ctx)) {
        tr_error("gsr: could not create resource structure: %u/%u/%u", object_id, object_instance_id, resource_id);
        return PT_API_INTERNAL_ERROR;
    }

    return edgeclient_set_resource_value_native(NULL, object_id, object_instance_id, resource_id, value, value_length);
}

// set a value in the cloud for obj_id/res_id to value
// process a string from /proc/stat and return cpu percentage
// 1st sample will always be zero because it requires previous state to compute
static float get_cpu()
{
    const char cmd_cpu_pct[] = "head -1 /proc/stat";    // get cpu status bash command
    float cpu_percent = 0;                              // return value
    struct cpu_info current_stats;                      // current info from /proc/stat
    char proc_stat[256];

    // previous cpu usage stats
    static struct cpu_info previous_stats = {"",0,0,0,0,0,0,0,0,0,0};

    // clear result of exec
    memset(proc_stat, 0, sizeof(proc_stat));

    // run cmd
    int ret = sys_exec(cmd_cpu_pct, proc_stat, sizeof(proc_stat));
    if (ret != 0) {
        return 0;
    }

    memset(&current_stats, 0, sizeof(current_stats));

    // pull the 1st line out of /proc/stat
    sscanf(proc_stat,
           "%s %16llu %16llu %16llu %16llu %16llu %16llu %16llu %16llu %16llu %16llu",
           current_stats.cpu,
           &current_stats.user,
           &current_stats.nice,
           &current_stats.system,
           &current_stats.idle,
           &current_stats.io_wait,
           &current_stats.irq,
           &current_stats.soft_irq,
           &current_stats.steal,
           &current_stats.guest,
           &current_stats.guest_nice);

    // calc all idle
    current_stats.all_idle = current_stats.idle +
                             current_stats.io_wait;

    // calc all cpu
    current_stats.non_idle = current_stats.user +
                             current_stats.nice +
                             current_stats.system +
                             current_stats.irq +
                             current_stats.soft_irq +
                             current_stats.steal;

    // calc totals
    current_stats.total =    current_stats.all_idle +
                             current_stats.non_idle;

    //if we have a previous sample then do the cpu percent
    if (strlen(previous_stats.cpu) > 0) {
        // get the diffs
        int total_diff  = current_stats.total - previous_stats.total;
        int idle_diff   = current_stats.all_idle - previous_stats.all_idle;
        // now make the cpu %
        cpu_percent = (float)(((float)total_diff - (float)idle_diff) / (float)total_diff)*100;
    }

    // save the current as previous for next run
    memcpy(&previous_stats, &current_stats, sizeof(previous_stats));

    return cpu_percent;
}

static inline void gsr_set_resource_helper_float(uint32_t obj_id, uint16_t obj_inst_id, uint16_t res_id, float value)
{
    pt_api_result_code_e eret = edgeclient_set_resource_value_native(NULL,
                                                                     obj_id,
                                                                     obj_inst_id,
                                                                     res_id,
                                                                     (uint8_t *)&value,
                                                                     sizeof(value));

    if (eret != PT_API_SUCCESS)
        tr_debug("EdgeClient update resource /%d/0/%d failed with code: %d", obj_id, res_id, eret);
}

static void gsr_set_resource_helper_int(uint32_t obj_id, uint16_t res_id, int64_t value)
{
    pt_api_result_code_e eret = edgeclient_set_resource_value_native(NULL,
                                                                     obj_id,
                                                                     0,
                                                                     res_id,
                                                                     (uint8_t *)&value,
                                                                     sizeof(value));

    if (eret != PT_API_SUCCESS)
        tr_debug("EdgeClient update resource /%d/0/%d failed with code: %d", obj_id, res_id, eret);
}

// updates gateway statistics resources
void gsr_update_gateway_stats_resources(void *arg)
{
    // CPU temperature in Celsius, whole degrees no decimal
    const char cmd_cpu_temp[] = "{ echo -1; cat /sys/class/hwmon/hwmon0/temp*_input 2>/dev/null; } | awk '{if (max<$1) max=$1} END {print max/1000}'";
    gsr_set_resource_helper_int(GATEWAY_STATS_OBJ_ID, GATEWAY_STATS_CPU_TEMP_RES_ID, int_exec(cmd_cpu_temp));

    // cpu usage
    gsr_set_resource_helper_float(GATEWAY_STATS_OBJ_ID, 0, GATEWAY_STATS_CPU_PCT_RES_ID, get_cpu());

    // ram in bytes
    const char cmd_ram_free[] = "awk '/^MemFree:/{ print $2*1024 }' /proc/meminfo";
    gsr_set_resource_helper_int(GATEWAY_STATS_OBJ_ID, GATEWAY_STATS_RAM_FREE_RES_ID, int_exec(cmd_ram_free));

    // disk info in megabytes
    const char cmd_disk_free[] = "df /home --output=avail | sed '$!d;s/ *//'";
    gsr_set_resource_helper_int(GATEWAY_STATS_OBJ_ID, GATEWAY_STATS_DISK_FREE_RES_ID, int_exec(cmd_disk_free));

    return;
}

// add gateway statistics
void gsr_add_gateway_stats_resources()
{
    int64_t int_default = 0;
    float float_default = 0;
    int64_t int_actual;

    // cpu temp
    gsr_create_resource(GATEWAY_STATS_OBJ_ID,
                        0,
                        GATEWAY_STATS_CPU_TEMP_RES_ID,
                        "cpu temp",
                        LWM2M_INTEGER,
                        OPERATION_READ,
                        (uint8_t *)&int_default,
                        sizeof(int_default),
                        NULL);

    // cpu usage percent
    gsr_create_resource(GATEWAY_STATS_OBJ_ID,
                        0,
                        GATEWAY_STATS_CPU_PCT_RES_ID,
                        "cpu usage",
                        LWM2M_FLOAT,
                        OPERATION_READ,
                        (uint8_t *)&float_default,
                        sizeof(float_default),
                        NULL);

    // ram total
    const char cmd_ram_total[] = "awk '/^MemTotal:/{ print $2*1024 }' /proc/meminfo";
    int_actual = int_exec(cmd_ram_total),
    gsr_create_resource(GATEWAY_STATS_OBJ_ID,
                        0,
                        GATEWAY_STATS_RAM_TOTAL_RES_ID,
                        "mem total",
                        LWM2M_INTEGER,
                        OPERATION_READ,
                        (uint8_t *)&int_actual,
                        sizeof(int_actual),
                        NULL);

    // ram free
    gsr_create_resource(GATEWAY_STATS_OBJ_ID,
                        0,
                        GATEWAY_STATS_RAM_FREE_RES_ID,
                        "mem free",
                        LWM2M_INTEGER,
                        OPERATION_READ,
                        (uint8_t *)&int_default,
                        sizeof(int_default),
                        NULL);

    // disk total
    const char cmd_disk_total[] = "df /home --output=size | sed '$!d;s/ *//'";
    int_actual = int_exec(cmd_disk_total);
    gsr_create_resource(GATEWAY_STATS_OBJ_ID,
                        0,
                        GATEWAY_STATS_DISK_TOTAL_RES_ID,
                        "disk total",
                        LWM2M_INTEGER,
                        OPERATION_READ,
                        (uint8_t *)&int_actual,
                        sizeof(int_actual),
                        NULL);

    // disk free
    gsr_create_resource(GATEWAY_STATS_OBJ_ID,
                        0,
                        GATEWAY_STATS_DISK_FREE_RES_ID,
                        "disk free",
                        LWM2M_INTEGER,
                        OPERATION_READ,
                        (uint8_t *)&int_default,
                        sizeof(int_default),
                        NULL);

    return;
}
