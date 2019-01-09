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
#ifndef EDGE_MUTEX_H
#define EDGE_MUTEX_H

#include <pthread.h>
#include <stdint.h>

/**
 * \defgroup EDGE_MUTEX Edge mutex API.
 * @{
 */

/** \file edge_mutex.h
 * \brief Edge Mutex API
 *
 * Definition of the Edge mutex API.
 *
 * This module exists to help testing mutexes. In tests we also use pthread mutexes.
 * Therefore we cannot mock them. Instead we have a library which calls pthread mutexes and can be mocked.
 * Because this module is based on pthread mutexes, more information is available entering for example: "man
 * pthread_mutex_init" in Linux with pthread man page installed. In Ubuntu this manual page is installed using
 * "apt install glibc-doc".
 */

typedef pthread_mutex_t edge_mutex_t;

/**
 * \brief Initializes a mutex.
 * \param mutex pointer to the mutex which should be initialized. The user is responsible to allocate the
 *        memory for the mutex data structure.
 * \param type is used for setting mutex type using pthread_mutexattr_settype. See `man
 * pthread_mutex_attr`. Allowed values are:
 *                        - PTHREAD_MUTEX_NORMAL
 *                        - PTHREAD_MUTEX_RECURSIVE
 *                        - PTHREAD_MUTEX_ERRORCHECK
 * _GNU_SOURCE compiler definition needs to be defined for these enums to be enabled.
 */
int32_t edge_mutex_init(edge_mutex_t *mutex, int32_t type);

/**
 * \brief Destroys a mutex. The user is responsible to deallocate the memory for the mutex structure.
 * \param mutex pointer to the mutex which should be destroyed.
 */
int32_t edge_mutex_destroy(edge_mutex_t *mutex);

/**
 * \brief Locks the mutex.
 * \param mutex is a pointer to the mutex structure.
 */
int32_t edge_mutex_lock(edge_mutex_t *mutex);

/**
 * \brief Unlocks the mutex.
 * \param mutex is a pointer to the mutex structure.
 */
int32_t edge_mutex_unlock(edge_mutex_t *mutex);

/**
 * @}
 * Close EDGE_MUTEX Doxygen group definition
 */

#endif
