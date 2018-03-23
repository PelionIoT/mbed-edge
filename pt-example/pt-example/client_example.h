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

#include <pthread.h>
#include <pt-client/pt_api.h>

struct reappearing_thread_params {
    const char *device_name;
    const char *endpoint_postfix;
    pthread_mutex_t mutex;
    void *sp; // stack
    int visible_time_seconds;
    int hidden_time_seconds;
    int temperature;
    bool visible;
    bool device_registered;
    bool unregister_devices_flag;
    bool quit_signal;
};

void unregister_test_device();
void device_registration_success(const char* device_id, void *userdata);
void device_registration_failure(const char* device_id, void *userdata);
void device_unregistration_success(const char* device_id, void *userdata);
void device_unregistration_failure(const char* device_id, void *userdata);

void reappearing_thread_stop();
void destroy_reappearing_device_thread_params(struct reappearing_thread_params *params);

pt_device_t *create_device(const char *device_id_string);

