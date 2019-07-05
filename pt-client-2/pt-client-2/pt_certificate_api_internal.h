/*
 * ----------------------------------------------------------------------------
 * Copyright 2019 ARM Ltd.
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

#ifndef PT_CERTIFICATE_API_INTERNAL_H
#define PT_CERTIFICATE_API_INTERNAL_H

typedef struct pt_device_cert_renewal_context_s {
    char *device_id;
    char *cert_name;
    char *request_id;
    void *userdata;
} pt_device_cert_renewal_context_t;

pt_status_t pt_device_init_certificate_renewal_resources(connection_id_t connection_id, const char *device_id);

#ifdef BUILD_TYPE_TEST

void pt_device_cert_renewal_context_free(pt_device_cert_renewal_context_t *ctx);
pt_status_t pt_device_certificate_renew_resource_callback(const connection_id_t connection_id,
                                                          const char *device_id,
                                                          const uint16_t object_id,
                                                          const uint16_t object_instance_id,
                                                          const uint16_t resource_id,
                                                          const uint8_t operation,
                                                          const uint8_t *value,
                                                          const uint32_t size,
                                                          void *userdata);

#endif // BUILD_TYPE_TEST

#endif // PT_CERTIFICATE_API_INTERNAL_H
