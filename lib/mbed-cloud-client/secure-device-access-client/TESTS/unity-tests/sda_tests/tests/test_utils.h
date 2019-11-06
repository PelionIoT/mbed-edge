// ----------------------------------------------------------------------------
// Copyright 2017-2019 ARM Ltd.
//  
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//  
//     http://www.apache.org/licenses/LICENSE-2.0
//  
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// ----------------------------------------------------------------------------

#ifndef __TEST_UTILS_H__
#define __TEST_UTILS_H__

#include <inttypes.h>
#include <stdbool.h>
#include <string.h>
#include "secure_device_access.h"
#include "sda_status_internal.h"


#ifdef __cplusplus
extern "C" {
#endif

/**
* Trust anchor key name should have the following format:
* mbed.ta.<public-key-sha256-fingerprint-uppercase>.
* The name is exactly 72 characters long – 8 characters for the prefix, 
* 64 characters for the fingerprint hex string.
**/
#define TEST_SDA_TRUST_ANCHOR_KEY_NAME_SIZE (8 + 64)

/** Sets the nonce value.
*
*@param uint64_t nonce - nonce value to set
*/
void test_sda_nonce_set(uint64_t nonce);


/** Sets provisioning setup and trusted anchor.
*
*@param trust_anchor -       pointer to trust anchor buffer
*@param trust_anchor_size -  size of  trust anchor buffer
*@param device_id -          pointer to device id data (optional for now)
*@param trust_anchor_size -  size of  device id data (optional for now)
*/
sda_status_e test_provisioning_setup(bool is_developer_set, const uint8_t *trust_anchor_name, size_t trust_anchor_name_size, 
                                    const uint8_t *der_trust_anchor, size_t der_trust_anchor_size, 
                                    const uint8_t *device_id, size_t device_id_size, 
                                    const uint8_t *endpoint_name, size_t endpoint_name_size);

#ifdef __cplusplus
}
#endif

#endif  // __TEST_UTILS_H__

