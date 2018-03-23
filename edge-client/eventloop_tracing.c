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

#define TRACE_GROUP "evtr"

#include "edge-client/eventloop_tracing.h"

#ifdef EDGE_EVENTLOOP_STATS_TRACING

#include <assert.h>
#include "mbed-trace/mbed_trace.h"
#include "nsdynmemLIB.h"
#include "ns_hal_init.h"
#include "eventOS_event.h"
#include "eventOS_event_timer.h"
#include "eventOS_scheduler.h"

#define EDGE_TASKLET_EVENT 123
static int8_t _tasklet_id = -1;
static mem_stat_t eventloop_stats = {0};

static void print_eventloop_stats()
{
    tr_debug("===== Eventloop heap stats =====");
    tr_debug("Sector size: %d", eventloop_stats.heap_sector_size);
    tr_debug("Allocated sector count: %d", eventloop_stats.heap_sector_alloc_cnt);
    tr_debug("Allocated bytes: %d", eventloop_stats.heap_sector_allocated_bytes);
    tr_debug("Max allocated bytes: %d", eventloop_stats.heap_sector_allocated_bytes_max);
    tr_debug("Total allocated bytes: %d", eventloop_stats.heap_alloc_total_bytes);
    tr_debug("Fail allocation count: %d", eventloop_stats.heap_alloc_fail_cnt);
    tr_debug("================================");
}

void edge_tasklet_func(arm_event_s *event)
{
    // skip the init event as there will be a timer event after
    if (event->event_type == EDGE_TASKLET_EVENT) {
        print_eventloop_stats();
    }
}

void eventloop_stats_init()
{
    ns_hal_init(NULL, MBED_CONF_MBED_CLIENT_EVENT_LOOP_SIZE, NULL, &eventloop_stats);
    eventOS_scheduler_mutex_wait();
    if (_tasklet_id < 0) {
        _tasklet_id = eventOS_event_handler_create(edge_tasklet_func, EDGE_TASKLET_EVENT);
        assert(_tasklet_id >= 0);
    }
    eventOS_scheduler_mutex_release();
    arm_event_t event = {
        .receiver = _tasklet_id,
        .sender = 0,
        .event_type = EDGE_TASKLET_EVENT,
        .event_id = 0,
        .data_ptr = NULL,
        .priority = ARM_LIB_MED_PRIORITY_EVENT,
        .event_data = 0
    };
    eventOS_event_timer_request_every(&event, 500);
}
#endif
