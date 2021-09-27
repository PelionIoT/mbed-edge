#include <stdint.h>
#include "CppUTestExt/MockSupport.h"
#include "cpputest-custom-types/value_pointer.h"
#include "mbed-trace/mbed_trace.h"
#include "mbed-client/m2minterfacefactory.h"
#include "mbed-client/m2mresource.h"
#include "edge-client/edge_client_internal.h"
#include "edge-client/edge_manifest_object.h"
#include <stdint.h>
#include <stddef.h>
#include "edge-client/edge_client.h"
#include <curl/curl.h>
extern "C" {
#include "common/integer_length.h"
#include "edge-client/reset_factory_settings.h"
#include "edge-client/edge_client_mgmt.h"
#ifdef MBED_EDGE_SUBDEVICE_FOTA
#include "fota/fota_component_defs.h"
#include "edge-client/subdevice_fota.h"
#endif // MBED_EDGE_SUBDEVICE_FOTA
}

void edgeclient_update_register()
{
    mock().actualCall("update_register_client");
}

void edgeclient_update_register_conditional()
{
    mock().actualCall("update_register_client_conditional");
}

bool edgeclient_endpoint_exists(const char *endpoint_name) {
    return (bool)(mock().actualCall("endpoint_exists")
                  .withParameter("endpoint_name", endpoint_name)
                  .returnIntValue());
}

bool edgeclient_resource_exists(const char *endpoint_name,
                                const uint16_t object_id,
                                const uint16_t object_instance_id,
                                const uint16_t resource_id) {
    return (bool)(mock().actualCall("resource_exists")
                  .withParameter("endpoint_name", endpoint_name)
                  .withParameter("object_id", object_id)
                  .withParameter("object_instance_id", object_instance_id)
                  .withParameter("resource_id", resource_id)
                  .returnIntValue());
}

uint32_t edgeclient_remove_objects_owned_by_client(void *client_context)
{
    return mock()
            .actualCall("remove_objects_owned_by_client")
            .withParameter("client_context", client_context)
            .returnUnsignedIntValue();
}

bool edgeclient_remove_resources_owned_by_client(void *client_context)
{
    mock().actualCall("remove_resources_owned_by_client")
            .withParameter("client_context", client_context);
    return true;
}

void edgeclient_create(const edgeclient_create_parameters_t *params, byoc_data_t *byoc_data)
{
    mock().actualCall("edgeclient_create")
          .withPointerParameter("params", (void *)params)
          .withPointerParameter("byoc_data", byoc_data);
}

void edgeclient_destroy() {
    mock().actualCall("edgeclient_destroy");
}

void edgeclient_connect() {
    mock().actualCall("edgeclient_connect");
}

bool edgeclient_add_endpoint(const char *endpoint_name, void *ctx) {
    return (bool) (mock().actualCall("add_endpoint")
                   .withParameter("endpoint_name", endpoint_name)
                   .withParameter("ctx", ctx).returnIntValue());
}

bool edgeclient_add_object(const char *endpoint_name, const uint16_t object_id) {
    mock().actualCall("add_object").withParameter("endpoint_name", endpoint_name).withParameter("object_id", object_id);
    return true;
}

bool edgeclient_add_object_instance(const char *endpoint_name, const uint16_t object_id, const uint16_t object_instance_id) {
    mock().actualCall("add_object_instance")
            .withParameter("endpoint_name", endpoint_name)
            .withParameter("object_id", object_id)
            .withParameter("object_instance_id", object_instance_id);
    return true;
}

bool edgeclient_remove_object_instance(const char *endpoint_name, const uint16_t object_id, const uint16_t object_instance_id)
{
    mock().actualCall("remove_object_instance")
            .withStringParameter("endpoint_name", endpoint_name)
            .withParameter("object_id", object_id)
            .withParameter("object_instance_id", object_instance_id);
    return true;
}

bool edgeclient_add_resource(const char *endpoint_name, const uint16_t object_id, const uint16_t object_instance_id, const uint16_t resource_id, const char *resource_name, Lwm2mResourceType resource_type, int opr, void *connection) {
    mock().actualCall("add_resource")
            .withParameter("endpoint_name", endpoint_name)
            .withParameter("object_id", object_id)
            .withParameter("object_instance_id", object_instance_id)
            .withParameter("resource_id", resource_id)
            .withParameter("resource_name", resource_name)
            .withParameter("resource_type", resource_type)
            .withParameter("opr", opr);
    return true;
}

bool edgeclient_verify_value(const uint8_t *value, const uint32_t value_length, Lwm2mResourceType resource_type)
{
    ValuePointer *value_pointer = new ValuePointer((uint8_t *) value, value_length);
    bool ret = (bool) mock()
                       .actualCall("edgeclient_verify_value")
                       .withParameterOfType("ValuePointer", "value", (void *) value_pointer)
                       .withParameter("value_length", value_length)
                       .withParameter("resource_type", resource_type)
                       .returnBoolValue();
    delete value_pointer;
    return ret;
}

bool edgeclient_get_resource_attributes(const char *endpoint_name,
                                        const uint16_t object_id,
                                        const uint16_t object_instance_id,
                                        const uint16_t resource_id,
                                        edgeclient_resource_attributes_t *attributes_out)
{
    return mock()
            .actualCall("get_resource_attributes")
            .withStringParameter("endpoint_name", endpoint_name)
            .withParameter("object_id", object_id)
            .withParameter("object_instance_id", object_instance_id)
            .withParameter("resource_id", resource_id)
            .withOutputParameter("attributes_out", attributes_out)
            .returnBoolValue();
}

bool edgeclient_get_endpoint_context(const char *endpoint_name, void **context_out)
{
    return mock()
            .actualCall("get_endpoint_context")
            .withStringParameter("endpoint_name", endpoint_name)
            .withOutputParameter("context_out", context_out)
            .returnBoolValue();
}

edgeclient_request_context_t *edgeclient_allocate_request_context(const char *uri,
                                                                  uint8_t *value,
                                                                  uint32_t value_length,
                                                                  uint8_t *token,
                                                                  uint8_t token_len,
                                                                  edgeclient_value_format_e value_format,
                                                                  uint8_t operation,
                                                                  Lwm2mResourceType resource_type,
                                                                  edgeclient_response_handler success_handler,
                                                                  edgeclient_response_handler failure_handler,
                                                                  edge_rc_status_e *rc_status,
                                                                  void *connection)
{
    ValuePointer *value_pointer = new ValuePointer((uint8_t *) value, value_length);
    ValuePointer *value_pointer2 = new ValuePointer((uint8_t *) token, token_len);
    edgeclient_request_context_t *ctx = (edgeclient_request_context_t *) mock()
                                                .actualCall("allocate_request_context")
                                                .withStringParameter("uri", uri)
                                                .withParameterOfType("ValuePointer", "value", (void *) value_pointer)
                                                .withUnsignedIntParameter("value_length", value_length)
                                                .withParameterOfType("ValuePointer", "token", (void *) value_pointer2)
                                                .withUnsignedIntParameter("token_len", token_len)
                                                .withIntParameter("value_format", value_format)
                                                .withUnsignedIntParameter("operation", operation)
                                                .withIntParameter("resource_type", resource_type)
                                                .withPointerParameter("success_handler", (void *) success_handler)
                                                .withPointerParameter("failure_handler", (void *) failure_handler)
                                                .returnPointerValue();
    ctx->connection = connection;

    delete value_pointer;
    delete value_pointer2;
    free(value); // Full implementation frees the value.
    return ctx;
}

void edgeclient_deallocate_request_context(edgeclient_request_context_t *request_context)
{
    mock().actualCall("deallocate_request_context").withPointerParameter("request_context", request_context);
}

pt_api_result_code_e edgeclient_update_resource_value(const char *endpoint_name,
                                                      const uint16_t object_id,
                                                      const uint16_t object_instance_id,
                                                      const uint16_t resource_id,
                                                      const uint8_t *value,
                                                      uint32_t value_length)
{
    ValuePointer *value_pointer = new ValuePointer((uint8_t *) value, value_length);

    pt_api_result_code_e ret = (pt_api_result_code_e) mock()
                                       .actualCall("update_resource_value")
                                       .withStringParameter("endpoint_name", endpoint_name)
                                       .withParameter("object_id", object_id)
                                       .withParameter("object_instance_id", object_instance_id)
                                       .withParameter("resource_id", resource_id)
                                       .withParameterOfType("ValuePointer", "value", (void *) value_pointer)
                                       .withParameter("value_length", value_length)
                                       .returnIntValue();
    delete value_pointer;
    return ret;
}

pt_api_result_code_e edgeclient_set_resource_value(const char *endpoint_name, const uint16_t object_id, const uint16_t object_instance_id, const uint16_t resource_id, const char *resource_name, const uint8_t *value, uint32_t value_length, Lwm2mResourceType resource_type, int opr, void* ctx) {
    ValuePointer *value_pointer = new ValuePointer((uint8_t*) value, value_length);

    pt_api_result_code_e ret = (pt_api_result_code_e) mock().actualCall("set_resource_value")
        .withStringParameter("endpoint_name", endpoint_name)
        .withParameter("object_id", object_id)
        .withParameter("object_instance_id", object_instance_id)
        .withParameter("resource_id", resource_id)
        .withParameterOfType("ValuePointer", "value", (void *) value_pointer)
        .withParameter("value_length", value_length)
        .withParameter("resource_type", resource_type)
        .withParameter("opr", opr)
        .withParameter("ctx", ctx)
        .returnIntValue();
    delete value_pointer;
    return ret;
}

bool edgeclient_get_resource_value(const char *endpoint_name, const uint16_t object_id, const uint16_t object_instance_id, const uint16_t resource_id, uint8_t **value_out, uint32_t *value_length_out) {
    mock().actualCall("get_resource_value")
            .withStringParameter("endpoint_name", endpoint_name)
            .withParameter("object_id", object_id)
            .withParameter("object_instance_id", object_instance_id)
            .withParameter("resource_id", resource_id)
            .withOutputParameter("value", value_out)
            .withOutputParameter("value_length", value_length_out);
    return true;
}

bool edgeclient_get_resource_value_and_attributes(const char *endpoint_name,
                                                  const uint16_t object_id,
                                                  const uint16_t object_instance_id,
                                                  const uint16_t resource_id,
                                                  uint8_t **value_out,
                                                  uint32_t *value_length_out,
                                                  edgeclient_resource_attributes_t *attributes)
{
    return mock()
            .actualCall("get_resource_value_and_attributes")
            .withStringParameter("endpoint_name", endpoint_name)
            .withParameter("object_id", object_id)
            .withParameter("object_instance_id", object_instance_id)
            .withParameter("resource_id", resource_id)
            .withOutputParameter("value", value_out)
            .withOutputParameter("value_length", value_length_out)
            .withOutputParameter("attributes", attributes)
            .returnBoolValue();
}

bool edgeclient_remove_endpoint(const char *endpoint_name)
{
    return mock().actualCall("remove_endpoint")
        .withStringParameter("endpoint_name", endpoint_name)
        .returnBoolValue();
}

const char* edgeclient_get_internal_id() {
    return mock().actualCall("get_internal_id")
        .returnStringValue();
}

const char* edgeclient_get_account_id() {
    return mock().actualCall("get_account_id")
        .returnStringValue();
}

const char* edgeclient_get_lwm2m_server_uri() {
    return mock().actualCall("get_lwm2m_server_uri")
        .returnStringValue();
}

const char* edgeclient_get_endpoint_name() {
    return mock().actualCall("get_endpoint_name")
        .returnStringValue();
}

bool edgeclient_is_shutting_down()
{
    return mock().actualCall("edgeclient_is_shutting_down")
            .returnBoolValue();
}

bool edgeclient_stop()
{
    return (bool)mock().actualCall("edgeclient_stop")
        .returnIntValue();
}

void rfs_add_factory_reset_resource()
{
    mock().actualCall("rfs_add_factory_reset_resource");
}

void rfs_finalize_reset_factory_settings()
{
    mock().actualCall("rfs_finalize_reset_factory_settings");
}

edge_device_list_t *edgeclient_devices()
{
    return (edge_device_list_t*) mock().actualCall("edgeclient_devices")
        .returnPointerValue();
}

pt_api_result_code_e edgeclient_renew_certificate(const char *certificate_name, int *detailed_error)
{
    return (pt_api_result_code_e) mock()
            .actualCall("edgeclient_renew_certificate")
            .withStringParameter("cert_name", certificate_name)
            .withOutputParameter("detailed_error", detailed_error)
            .returnIntValue();
}

pt_api_result_code_e edgeclient_request_est_enrollment(const char *certificate_name,
                                                       uint8_t *csr,
                                                       const size_t csr_length,
                                                       void *context)
{
    mock().setData("est_csr_parameter", csr);
    mock().setData("est_context_parameter", context);
    return (pt_api_result_code_e) mock().actualCall("edgeclient_request_est_enrollment")
        .withStringParameter("certificate_name", certificate_name)
        .withMemoryBufferParameter("csr", csr, csr_length)
        .withPointerParameter("context", context)
        .returnIntValue();
}
#ifdef MBED_EDGE_SUBDEVICE_FOTA
int get_component_name(char* c_name) {
    return mock().actualCall("get_component_name").withOutputParameter("component_name",c_name).returnIntValue();
}
void free_subdev_context_buffers(void) {
    mock().actualCall("free_subdev_context_buffers");
}
unsigned int get_component_id() {
    return mock().actualCall("get_component_id").returnIntValue();
}
void get_version(fota_component_version_t *version) {
    mock().actualCall("get_version").withOutputParameter("Version", version);
}

void get_vendor_id(uint8_t* v_id) {
    mock().actualCall("get_vendor_id").withOutputParameter("vendor_id", v_id);
}
void get_class_id(uint8_t* c_id) {
    mock().actualCall("get_class_id").withOutputParameter("class_id", c_id);
}
void get_uri(char* c_url) {
    mock().actualCall("get_uri").withOutputParameter("url", c_url);
}
int start_download(char* path) {
    return mock().actualCall("start_download").withOutputParameter("path", path).returnIntValue();
}
void subdevice_abort_update(int err, char* msg) {
    mock().actualCall("subdevice_abort_update").withParameter("error", err).withParameter("error_message", msg);
}
size_t get_manifest_fw_size() {
    return mock().actualCall("get_manifest_fw_size").returnLongIntValue();
}

int subdevice_init_buff() {
    return mock().actualCall("subdevice_init_buff").returnIntValue();
}

int update_result_resource(char* device_id, uint8_t val) {
    return mock().actualCall("update_result_resource").withParameter("device_id", device_id).withParameter("value", val).returnIntValue();
}

int update_state_resource(char* device_id, uint8_t val) {
    return mock().actualCall("update_state_resource").withParameter("device_id", device_id).withParameter("value", val).returnIntValue();
}

void fota_component_get_curr_version(unsigned int comp_id, fota_component_version_t *version) {
    mock().actualCall("fota_component_get_curr_version").withParameter("component_id", comp_id).withOutputParameter("version", version);
}
int fota_component_version_int_to_semver(fota_component_version_t version, char *sem_ver) {
    return mock().actualCall("fota_component_version_int_to_semver").withParameter("version", version).withOutputParameter("curr_version", sem_ver).returnIntValue();
}
void get_endpoint(char* endpoint,const char* uri_path) {
    mock().actualCall("get_endpoint").withParameter("uri_path", uri_path).withOutputParameter("endpoint", endpoint);
}

pt_api_result_code_e subdevice_set_resource_value(const char *endpoint_name, const uint16_t object_id, const uint16_t object_instance_id, 
                                                const uint16_t resource_id, const char* resource_name, const uint8_t *value, uint32_t value_length, 
                                                Lwm2mResourceType resource_type, int opr, void* ctx) {
    tr_info("subdevice_set_resource_value mock");
    ValuePointer *value_pointer = new ValuePointer((uint8_t*) value, value_length);
    pt_api_result_code_e ret = (pt_api_result_code_e) mock().actualCall("set_resource_value")
        .withStringParameter("endpoint_name", endpoint_name)
        .withParameter("object_id", object_id)
        .withParameter("object_instance_id", object_instance_id)
        .withParameter("resource_id", resource_id)
        .withParameterOfType("ValuePointer", "value", (void *) value_pointer)
        .withParameter("value_length", value_length)
        .withParameter("resource_type", resource_type)
        .withParameter("opr", opr)
        .withParameter("ctx", ctx)
        .returnIntValue();
    delete value_pointer;
    return ret;
}

#endif