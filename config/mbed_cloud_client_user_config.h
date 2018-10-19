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

/*
 * Minimal configuration for using mbed-cloud-client
 */

#ifndef MBED_CLOUD_CLIENT_USER_CONFIG_H
#define MBED_CLOUD_CLIENT_USER_CONFIG_H

#define MBED_CLOUD_CLIENT_SUPPORT_CLOUD
#define MBED_CLOUD_CLIENT_ENDPOINT_TYPE          "MBED_GW"
#define MBED_CLOUD_CLIENT_TRANSPORT_MODE_TCP
#define MBED_CLOUD_CLIENT_LIFETIME               3600

#define SN_COAP_MAX_BLOCKWISE_PAYLOAD_SIZE       1024
#define SN_COAP_DUPLICATION_MAX_MSGS_COUNT       0
#define SN_COAP_DISABLE_RESENDINGS               1

/* set download buffer size in bytes (min. 1024 bytes) */
#define MBED_CLOUD_CLIENT_UPDATE_BUFFER          (2 * 1024 * 1024)

/* set the TCP KEEPALIVE values */
#define MBED_CLIENT_TCP_KEEPALIVE_INTERVAL 60
#define MBED_CLIENT_TCP_KEEPALIVE_TIME 60

#endif /* MBED_CLIENT_USER_CONFIG_H */

