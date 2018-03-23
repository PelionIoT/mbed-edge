/*
 *  Minimal configuration for using mbed-cloud-client
 *
 * Copyright (c) 2016 ARM Limited. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 * Licensed under the Apache License, Version 2.0 (the License); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef MBED_CLOUD_CLIENT_USER_CONFIG_H
#define MBED_CLOUD_CLIENT_USER_CONFIG_H

#define MBED_CLOUD_CLIENT_SUPPORT_CLOUD
#define MBED_CLOUD_CLIENT_ENDPOINT_TYPE          "MBED_GW"
#define MBED_CLOUD_CLIENT_TRANSPORT_MODE_TCP
#define MBED_CLOUD_CLIENT_LIFETIME               3600

#define SN_COAP_MAX_BLOCKWISE_PAYLOAD_SIZE       1024

/* set download buffer size in bytes (min. 1024 bytes) */
#define MBED_CLOUD_CLIENT_UPDATE_BUFFER          (2 * 1024 * 1024)

// Specify the directory where to store MBed Cloud Client configurations (KCM).
// Your factory process must be aligned with this setting, it has to use same path.
// By default go to current folder ./mcc_config, WORKING and BACKUP will be made there.
// NOTE! Do not add trailing / to the paths.
#define MBED_CLOUD_CLIENT_CONFIG_DIR "/mnt/kcm"

#define SN_COAP_DUPLICATION_MAX_MSGS_COUNT       0
#define SN_COAP_DISABLE_RESENDINGS               1

#endif /* MBED_CLOUD_CLIENT_USER_CONFIG_H */
