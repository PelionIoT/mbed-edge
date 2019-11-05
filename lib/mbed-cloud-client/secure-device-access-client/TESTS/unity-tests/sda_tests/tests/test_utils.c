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

#include "test_utils.h"
#include "sda_nonce_mgr.h"
#include "factory_configurator_client.h"
#include "sda_trust_anchor.h"
#include "kcm_defs.h"
#include "key_config_manager.h"
#include "factory_configurator_client.h"
#include "fcc_defs.h"


extern const char g_device_id_parameter_name[];

void test_sda_nonce_set(uint64_t nonce)
{
    // push to circular buffer
    circ_buf_insert(nonce);
}

sda_status_e test_provisioning_setup(bool is_developer_set, const uint8_t *trust_anchor_name, size_t trust_anchor_name_size,
                                    const uint8_t *der_trust_anchor, size_t der_trust_anchor_size, 
                                    const uint8_t *device_id, size_t device_id_size,
                                    const uint8_t *endpoint_name, size_t endpoint_name_size) {
    fcc_status_e fcc_status = FCC_STATUS_SUCCESS;
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;

    //Check parameters
    if (der_trust_anchor == NULL || der_trust_anchor_size == 0) {
        return SDA_STATUS_INVALID_REQUEST;
    }
    if (der_trust_anchor_size != SDA_TRUST_ANCHOR_SIZE) {
        return SDA_STATUS_INVALID_REQUEST;
    }

    if (is_developer_set) {
        //Call to fcc development flow
        fcc_status = fcc_developer_flow();
        if (fcc_status != FCC_STATUS_SUCCESS) {
            return SDA_STATUS_DEVICE_INTERNAL_ERROR;
        }
    }


    //Store trust anchor
    kcm_status = kcm_item_store(trust_anchor_name, trust_anchor_name_size, KCM_PUBLIC_KEY_ITEM, true, der_trust_anchor, der_trust_anchor_size, NULL);
    if (kcm_status == KCM_STATUS_FILE_EXIST) {
        return SDA_STATUS_VERIFICATION_ERROR;
    } 
    if (kcm_status != KCM_STATUS_SUCCESS) {
        return SDA_STATUS_DEVICE_INTERNAL_ERROR;
    }

    //Store device id data in case it was sent
    if (device_id != NULL && device_id_size != 0) {
        kcm_status = kcm_item_store((uint8_t *)g_device_id_parameter_name, strlen(g_device_id_parameter_name), KCM_CONFIG_ITEM, true, device_id, device_id_size, NULL);
        if (kcm_status != KCM_STATUS_SUCCESS) {
            return SDA_STATUS_DEVICE_INTERNAL_ERROR;
        }
    }

    if (endpoint_name != NULL && endpoint_name_size != 0) {
        kcm_status = kcm_item_delete((const uint8_t *)g_fcc_endpoint_parameter_name, strlen(g_fcc_endpoint_parameter_name), KCM_CONFIG_ITEM);
        kcm_status = kcm_item_store((uint8_t *)g_fcc_endpoint_parameter_name, strlen(g_fcc_endpoint_parameter_name), KCM_CONFIG_ITEM, true, endpoint_name, endpoint_name_size, NULL);
        if (kcm_status != KCM_STATUS_SUCCESS) {
            return SDA_STATUS_DEVICE_INTERNAL_ERROR;
        }
    }

    return SDA_STATUS_SUCCESS;
 }

