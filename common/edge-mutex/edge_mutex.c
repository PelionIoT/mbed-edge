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
#ifndef _WIN32
#include <pthread.h>
#endif
#include "common/edge_mutex.h"
#ifdef _WIN32
#include <errno.h>
#endif

/**
 *
 *
 */
int32_t edge_mutex_init(edge_mutex_t *mutex, int32_t type)
{
#ifdef _WIN32
    if (!mutex || type < EDGE_MUTEX_NORMAL || type > EDGE_MUTEX_ERRORCHECK) return EINVAL;
    mutex->owner = 0;
    mutex->depth = 0;
    mutex->type = type;
    mutex->id = 0;
    mutex->semaphore = 0;
    if (type == EDGE_MUTEX_NORMAL)
        return pal_osSemaphoreCreate(1, &mutex->semaphore) == PAL_SUCCESS ? 0 : EAGAIN;
    return pal_osMutexCreate(&mutex->id) == PAL_SUCCESS ? 0 : EAGAIN;
#else
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, type);
    int32_t ret = (int32_t) pthread_mutex_init(mutex, &attr);
    pthread_mutexattr_destroy(&attr);

    return ret;
#endif
}

int32_t edge_mutex_destroy(edge_mutex_t *mutex)
{
#ifdef _WIN32
    if (!mutex || (!mutex->id && !mutex->semaphore)) return EINVAL;
    if (InterlockedCompareExchange(&mutex->owner, 0, 0)) return EBUSY;
    if (mutex->type == EDGE_MUTEX_NORMAL)
        return pal_osSemaphoreDelete(&mutex->semaphore) == PAL_SUCCESS ? 0 : EINVAL;
    return pal_osMutexDelete(&mutex->id) == PAL_SUCCESS ? 0 : EINVAL;
#else
    return (int32_t) pthread_mutex_destroy(mutex);
#endif
}

int32_t edge_mutex_lock(edge_mutex_t *mutex)
{
#ifdef _WIN32
    if (!mutex || (!mutex->id && !mutex->semaphore)) return EINVAL;
    LONG owner = (LONG)pal_osThreadGetId();
    if (mutex->type == EDGE_MUTEX_ERRORCHECK &&
        InterlockedCompareExchange(&mutex->owner, 0, 0) == owner) return EDEADLK;
    palStatus_t status = mutex->type == EDGE_MUTEX_NORMAL
        ? pal_osSemaphoreWait(mutex->semaphore, PAL_RTOS_WAIT_FOREVER, NULL)
        : pal_osMutexWait(mutex->id, PAL_RTOS_WAIT_FOREVER);
    if (status != PAL_SUCCESS) return EINVAL;
    InterlockedExchange(&mutex->owner, owner);
    ++mutex->depth;
    return 0;
#else
    return (int32_t) pthread_mutex_lock(mutex);
#endif
}

int32_t edge_mutex_unlock(edge_mutex_t *mutex)
{
#ifdef _WIN32
    if (!mutex || (!mutex->id && !mutex->semaphore)) return EINVAL;
    if (InterlockedCompareExchange(&mutex->owner, 0, 0) != (LONG)pal_osThreadGetId()) return EPERM;
    if (--mutex->depth == 0) InterlockedExchange(&mutex->owner, 0);
    palStatus_t status = mutex->type == EDGE_MUTEX_NORMAL
        ? pal_osSemaphoreRelease(mutex->semaphore) : pal_osMutexRelease(mutex->id);
    return status == PAL_SUCCESS ? 0 : EINVAL;
#else
    return (int32_t) pthread_mutex_unlock(mutex);
#endif
}
