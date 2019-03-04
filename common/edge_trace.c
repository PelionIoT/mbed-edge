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
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <unistd.h>
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "common/edge_mutex.h"
#include "common/edge_trace.h"
#include "common/test_support.h"
#include "common/edge_time.h"
#include "mbed-trace/mbed_trace.h"
#include <sys/types.h>
#include <sys/syscall.h>
/**
 * \brief Trace prefix string length. Trace prefix format: YYYY-MM-DD hh:mm:ss.mmm tid:xxxxxxxxxx with one trailing
 * whitespace (39 chars + trailing nil)
 */
#define TRACE_PREFIX_SIZE 40

/*
 * \brief holds the current timestamp string
 */
EDGE_LOCAL char *trace_prefix;

/**
 * \brief The mutex used for ensuring the thread safety of the mbed-trace logger.
 */
EDGE_LOCAL edge_mutex_t trace_mutex;

/**
 * \brief The function to initialize the mutex for mbed-trace.
 */
EDGE_LOCAL void trace_mutex_init()
{
    /* The mutex needs to be recursive, because there are trace calls like
       ```tr_dbg("Something: %s", tr_arr(funny));```. */
    int32_t result = edge_mutex_init(&trace_mutex, PTHREAD_MUTEX_RECURSIVE);
    assert(0 == result);
}

/**
 * \brief The function to destroy the mutex for mbed-trace.
 */
EDGE_LOCAL void trace_mutex_destroy()
{
    int32_t result = edge_mutex_destroy(&trace_mutex);
    assert(0 == result);
}

/**
 * \brief The function to implement the mutex locking for mbed-trace.
 */
EDGE_LOCAL void trace_mutex_wait()
{
    int32_t result = edge_mutex_lock(&trace_mutex);
    assert(0 == result);
}

/**
 * \brief The function to implement the mutex releasing for mbed-trace.
 */
EDGE_LOCAL void trace_mutex_release()
{
    int32_t result = edge_mutex_unlock(&trace_mutex);
    assert(0 == result);
}

EDGE_LOCAL char *edge_trace_prefix(size_t size)
{
    (void) size;

#define failed_time_prefix "No time! "

    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    uint64_t sec;
    uint64_t ns;

    edgetime_get_real_in_ns(&sec, &ns);

    if (NULL != t) {
        pid_t tid = syscall(__NR_gettid);
        strftime(trace_prefix, TRACE_PREFIX_SIZE, "%F %H:%M:%S.", t);
        sprintf(trace_prefix + 19, ".%03d tid:%7d ", (int) (ns / 1.0e6), (int) tid);
    } else {
        strncpy(trace_prefix, failed_time_prefix, TRACE_PREFIX_SIZE);
    }
    return trace_prefix;
}

void edge_trace_init(int color_mode)
{
    if (!color_mode) {
        // Remove color mode and clean the log from ANSI color code clutter.
        mbed_trace_config_set(mbed_trace_config_get() & ~TRACE_MODE_COLOR);
    }

    // force stdout to line buffering
    setvbuf(stdout, NULL, _IOLBF, BUFSIZ);

    mbed_trace_init();
    trace_mutex_init();
// enabling following will require to expecting wait mutexes for every trace during the tests
#ifndef BUILD_TYPE_TEST
    mbed_trace_mutex_wait_function_set(trace_mutex_wait);
    mbed_trace_mutex_release_function_set(trace_mutex_release);
#endif
    // Initialize timestamp pointer and the prefix function
    trace_prefix = calloc(TRACE_PREFIX_SIZE, sizeof(char));
    mbed_trace_prefix_function_set(&edge_trace_prefix);
}

void edge_trace_destroy()
{
    mbed_trace_prefix_function_set(NULL);
    free(trace_prefix);
    trace_prefix = NULL;
// enabling following will require to expecting wait mutexes for every trace during the tests
#ifndef BUILD_TYPE_TEST
    mbed_trace_mutex_wait_function_set(NULL);
    mbed_trace_mutex_release_function_set(NULL);
#endif
    trace_mutex_destroy();
    mbed_trace_free();
}
