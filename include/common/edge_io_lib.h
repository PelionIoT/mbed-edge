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

#ifndef EDGE_IO_LIB_H
#define EDGE_IO_LIB_H

#include <stdbool.h>

/**
 * \defgroup EDGE_IO_LIB Library for implementing various OS Input / Output related functionality
 *                       that is needed by Edge Core or related components.
 * @{
 */

/**
 * \file edge_io_lib.h
 * \brief Testable functions relating to file input/output.
 */

/**
 * \brief Check if a file exists using underlying OS call.
 *
 * \param path Path to the file to check.
 * \return true -  the file exists.
 *         false - the file doesn't exist.
 */
bool edge_io_file_exists(const char *path);

/**
 * \brief Acquires a lock file for the given Unix Domain socket path.
 *        The lock file will the given socket path with '.lock' appended to it.
 * \param path Path to the Unix Domain Socket file.
 * \param lock_fd The returned file descriptor for the lock file. It's needed for releasing the lock.
 * \return true If acquiring the socket lock succeeded.
 *         fail If acquiring the socket lock failed.
 */
bool edge_io_acquire_lock_for_socket(const char *path, int *lock_fd);

/**
 * \brief Releases the lock and deletes the lock file for the Unix Domain socket.
 *        The lock file will the given socket path with '.lock' appended to it.
 * \param path Path to the Unix Domain Socket file.
 * \param lock_fd The file corresponding to the lock file that was returned by edge_io_acquire_lock_for_socket.
 * \return true  Releasing the lock for the socket succeeded.
 *         false Releasing the lock for the socket failed.
 */
bool edge_io_release_lock_for_socket(const char *path, int lock_fd);

/**
 * \brief Removes the file for the given path
 * \return 0 If removing the file succeeded.
 *         For other return values, see 'man 2 unlink'.
 */
int edge_io_unlink(const char *path);

/**
 * @}
 * Close EDGE_IO_LIB Doxygen group definition
 */

#endif
