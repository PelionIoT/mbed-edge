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
#include "CppUTestExt/MockSupport.h"
extern "C" {
#include "common/edge_mutex.h"

/*
 * Edge mutexes are needed to
 * */

int32_t edge_mutex_init(edge_mutex_t *mutex, int32_t type)
{
    return mock()
            .actualCall("edge_mutex_init")
            .withIntParameter("type", type)
            .withPointerParameter("mutex", (void *) mutex)
            .returnIntValue();
}

int32_t edge_mutex_destroy(edge_mutex_t *mutex)
{
    return mock().actualCall("edge_mutex_destroy").withPointerParameter("mutex", (void *) mutex).returnIntValue();
}

int32_t edge_mutex_lock(edge_mutex_t *mutex)
{
    return mock().actualCall("edge_mutex_lock").withPointerParameter("mutex", (void *) mutex).returnIntValue();
}

int32_t edge_mutex_unlock(edge_mutex_t *mutex)
{
    return mock().actualCall("edge_mutex_unlock").withPointerParameter("mutex", (void *) mutex).returnIntValue();
}
} /* extern "C" */
