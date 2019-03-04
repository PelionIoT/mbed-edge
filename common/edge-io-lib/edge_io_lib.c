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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>
#include <stdbool.h>
#define TRACE_GROUP "edge-io"
#include "mbed-trace/mbed_trace.h"
#include "common/edge_io_lib.h"

#ifdef BUILD_TYPE_TEST
int mocked_open(const char *__file, int __oflagv, mode_t mode);
int mocked_flock(int __fd, int __operation);
int mocked_access(const char *__name, int __type);
int mocked_unlink(const char *__name);

#define access mocked_access
#define open mocked_open
#define flock mocked_flock
#define unlink mocked_unlink
#endif

bool edge_io_file_exists(const char *path)
{
    if (-1 != access(path, F_OK)) {
        return true;
    } else {
        return false;
    }
}

bool edge_io_acquire_lock_for_socket(const char *path, int *lock_fd)
{
    char *lock_filename = NULL;
    if (-1 == asprintf(&lock_filename, "%s.lock", path)) {
        return false;
    }

    // Open the lock file.
    *lock_fd = open(lock_filename, O_RDONLY | O_CREAT, 0600);
    if (*lock_fd == -1) {
        tr_err("The socket lock file '%s' cannot be created. Please check the permissions!", lock_filename);
        goto cannot_create_socket;
    }

    // Acquire the lock.
    int ret = flock(*lock_fd, LOCK_EX | LOCK_NB);
    if (ret != 0) {
        tr_err("The socket lock '%s' is held by another process. Is there another Edge Core running?", lock_filename);
        close(*lock_fd);
        *lock_fd = -1;
        goto cannot_create_socket;
    }

    free(lock_filename);
    return true;

cannot_create_socket:
    free(lock_filename);
    return false;
}

bool edge_io_release_lock_for_socket(const char *path, int lock_fd)
{
    bool ret_val = true;
    char *lock_filename = NULL;
    if (-1 == asprintf(&lock_filename, "%s.lock", path)) {
        return false;
    }
    int ret = flock(lock_fd, LOCK_UN | LOCK_NB);
    if (ret != 0) {
        tr_err("Cannot unlock the socket lock: %s", lock_filename);
        ret_val = false;
    }
    if (0 != edge_io_unlink(lock_filename)) {
        tr_err("Cannot remove the socket lock file: %s", lock_filename);
        ret_val = false;
    }
    free(lock_filename);
    return ret_val;
}

int edge_io_unlink(const char *path)
{
    return unlink(path);
}
