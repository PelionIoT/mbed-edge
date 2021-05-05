
#define TRACE_GROUP "edgecc"
#include <stdio.h>
#include <stdint.h>
#include "fcc_defs.h"
#include "factory_configurator_client.h"
#include "key_config_manager.h"
#include "edge-client/edge_client.h"
#include "CppUTestExt/MockSupport.h"

#ifdef __cplusplus
extern "C" {
#endif

const char g_fcc_use_bootstrap_parameter_name[] = "";
const char g_fcc_lwm2m_server_ca_certificate_name[] = "";
const char g_fcc_lwm2m_device_certificate_name[] = "";
const char g_fcc_lwm2m_device_private_key_name[] = "";
const char g_fcc_lwm2m_server_uri_name[] = "";
const char g_fcc_endpoint_parameter_name[] = "";
const char g_fcc_device_serial_number_parameter_name[] = "";
const char g_fcc_device_type_parameter_name[] = "";
const char g_fcc_hardware_version_parameter_name[] = "";
const char g_fcc_memory_size_parameter_name[] = "";
const char g_fcc_manufacturer_parameter_name[] = "";
const char g_fcc_model_number_parameter_name[] = "";

fcc_status_e fcc_storage_delete(void)
{
    return (fcc_status_e)mock()
            .actualCall("fcc_storage_delete")
            .returnUnsignedIntValue();
}

fcc_status_e fcc_verify_device_configured_4mbed_cloud(void)
{
    return (fcc_status_e)mock()
            .actualCall("fcc_verify_device_configured_4mbed_cloud")
            .returnIntValue();
}

fcc_status_e fcc_init(void) {
    mock().actualCall("fcc_init");
    return FCC_STATUS_SUCCESS;
}

fcc_status_e fcc_finalize(void) {
    mock().actualCall("fcc_finalize");
    return FCC_STATUS_SUCCESS;
}

kcm_status_e kcm_item_delete(const uint8_t *kcm_item_name, size_t kcm_item_name_len, kcm_item_type_e kcm_item_type) {
    return KCM_STATUS_SUCCESS;
}

kcm_status_e kcm_item_store(const uint8_t *kcm_item_name, size_t kcm_item_name_len, kcm_item_type_e kcm_item_type, bool kcm_item_is_factory, const uint8_t *kcm_item_data, size_t kcm_item_data_size, const kcm_security_desc_s security_desc) {
    return KCM_STATUS_SUCCESS;
}

fcc_status_e fcc_developer_flow(void) {
    return FCC_STATUS_SUCCESS;
}

kcm_status_e kcm_factory_reset(void) {
    return (kcm_status_e) mock().actualCall("kcm_factory_reset").returnIntValue();
}

fcc_status_e fcc_bundle_handler(const uint8_t *encoded_blob, size_t encoded_blob_size, uint8_t **bundle_response_out, size_t *bundle_response_size_out) {
    return (fcc_status_e) mock().actualCall("fcc_bundle_handler").returnIntValue();
}

#ifdef __cplusplus
}
#endif
