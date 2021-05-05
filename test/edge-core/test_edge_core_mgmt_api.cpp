#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include "CppUTest/TestHarness.h"
#include "CppUTestExt/MockSupport.h"

#include <string.h>
#include "jansson.h"
#include "cpputest-custom-types/value_pointer.h"

extern "C"
{
#include "ns_list.h"
#include "edge-core/mgmt_api_internal.h"
#include "edge-client/edge_client_mgmt.h"
#include "common/constants.h"
#include "edge-client/edge_client.h"
#include "edge-core/protocol_api_internal.h"
}

static int32_t running_id;

static int mocked_pt_write_function(struct connection *connection, char *data, size_t len);
static int mocked_mgmt_write_function(struct connection *connection, char *data, size_t len);

static void expect_mutexing()
{
    mock().expectOneCall("edge_mutex_lock").withPointerParameter("mutex", (void *) &rpc_mutex).andReturnValue(0);
    mock().expectOneCall("edge_mutex_unlock").withPointerParameter("mutex", (void *) &rpc_mutex).andReturnValue(0);
}

static char *test_msg_generate_id()
{
    char *result;

    asprintf(&result, "%d", running_id);
    running_id++;
    return result;
}

TEST_GROUP(edge_core_mgmt) {
    void setup(){
        running_id = 314159;
        rpc_set_generate_msg_id(test_msg_generate_id);
    }

    void teardown()
    {
        expect_mutexing();
        rpc_destroy_messages();
    }
};

static json_t *make_request()
{
    json_t *request = json_object();
    json_object_set_new(request, "id", json_string("123"));
    json_object_set_new(request, "jsonrpc", json_string("2.0"));
    json_object_set_new(request, "method", json_string("write_resource"));
    return request;
}

TEST(edge_core_mgmt, null_device_list)
{
    mock().expectOneCall("edgeclient_devices")
        .andReturnValue((void*) NULL);

    json_t *request = make_request();
    json_t *params = json_object();
    json_object_set_new(request, "params", params);
    json_t *result = NULL;

    int rc = devices(request, params, &result, NULL);

    CHECK_EQUAL(1, rc);
    CHECK_EQUAL(JSONRPC_INTERNAL_ERROR, json_integer_value(json_object_get(result, "code")));
    STRCMP_EQUAL("Internal error", json_string_value(json_object_get(result, "message")));
    STRCMP_EQUAL("Device list request failed.", json_string_value(json_object_get(result, "data")));

    json_decref(request);
    json_decref(result);
    mock().checkExpectations();
}

TEST(edge_core_mgmt, empty_device_list)
{
    // This list is freed in the tested function.
    edge_device_list_t *devicelist = (edge_device_list_t*) malloc(sizeof(edge_device_list_t));
    ns_list_init(devicelist);

    mock().expectOneCall("edgeclient_devices")
        .andReturnValue(devicelist);

    json_t *request = make_request();
    json_t *params = json_object();
    json_object_set_new(request, "params", params);
    json_t *result = NULL;

    int rc = devices(request, params, &result, NULL);

    CHECK_EQUAL(0, rc);
    CHECK_EQUAL(0, json_array_size(json_object_get(result, "data")));

    json_decref(request);
    json_decref(result);
    mock().checkExpectations();
}

TEST(edge_core_mgmt, devices_in_device_list_no_resources)
{
    // This list is freed in the tested function.
    edge_device_list_t *devicelist = (edge_device_list_t*) malloc(sizeof(edge_device_list_t));
    ns_list_init(devicelist);
    edge_device_entry_t *entry = (edge_device_entry_t*) malloc(sizeof(edge_device_entry_t));
    entry->name = strdup("ep1");

    edge_device_resource_list_t *resources = (edge_device_resource_list_t*) malloc(sizeof(edge_device_resource_list_t));
    ns_list_init(resources);
    entry->resources = resources;

    ns_list_add_to_end(devicelist, entry);

    mock().expectOneCall("edgeclient_devices")
        .andReturnValue(devicelist);

    json_t *request = make_request();
    json_t *params = json_object();
    json_object_set_new(request, "params", params);
    json_t *result = NULL;

    int rc = devices(request, params, &result, NULL);

    CHECK_EQUAL(0, rc);
    json_t *data_arr = json_object_get(result, "data");
    CHECK_EQUAL(1, json_array_size(data_arr));
    json_t *data_element = json_array_get(data_arr, 0);

    STRCMP_EQUAL("ep1", json_string_value(json_object_get(data_element, "endpointName")));
    CHECK_EQUAL(0, json_array_size(json_object_get(data_element, "resources")));

    json_decref(request);
    json_decref(result);
    mock().checkExpectations();
}

TEST(edge_core_mgmt, devices_in_device_list_resources)
{
    // This list is freed in the tested function.
    edge_device_list_t *devicelist = (edge_device_list_t*) malloc(sizeof(edge_device_list_t));
    ns_list_init(devicelist);
    edge_device_entry_t *entry = (edge_device_entry_t*) malloc(sizeof(edge_device_entry_t));
    entry->name = strdup("ep1");

    edge_device_resource_list_t *resources = (edge_device_resource_list_t*) malloc(sizeof(edge_device_resource_list_t));
    ns_list_init(resources);
    entry->resources = resources;

    edge_device_resource_entry_t *res1 = (edge_device_resource_entry_t*) malloc(sizeof(edge_device_resource_entry_t));
    edge_device_resource_entry_t *res2 = (edge_device_resource_entry_t*) malloc(sizeof(edge_device_resource_entry_t));
    res1->uri = strdup("res1");
    res1->type = LWM2M_STRING;
    res1->operation = OPERATION_READ;
    res2->uri = strdup("res2");
    res2->type = LWM2M_INTEGER;
    res2->operation = OPERATION_WRITE;

    ns_list_add_to_end(resources, res1);
    ns_list_add_to_end(resources, res2);
    ns_list_add_to_end(devicelist, entry);

    mock().expectOneCall("edgeclient_devices")
        .andReturnValue(devicelist);

    json_t *request = make_request();
    json_t *params = json_object();
    json_object_set_new(request, "params", params);
    json_t *result = NULL;

    int rc = devices(request, params, &result, NULL);

    CHECK_EQUAL(0, rc);
    json_t *data_arr = json_object_get(result, "data");
    CHECK_EQUAL(1, json_array_size(data_arr));
    json_t *data_element = json_array_get(data_arr, 0);

    STRCMP_EQUAL("ep1", json_string_value(json_object_get(data_element, "endpointName")));
    json_t *resource_arr = json_object_get(data_element, "resources");
    CHECK_EQUAL(2, json_array_size(resource_arr));
    STRCMP_EQUAL("res1", json_string_value(json_object_get(json_array_get(resource_arr, 0), "uri")));
    STRCMP_EQUAL("res2", json_string_value(json_object_get(json_array_get(resource_arr, 1), "uri")));

    json_decref(request);
    json_decref(result);
    mock().checkExpectations();
}

TEST(edge_core_mgmt, read_resource_no_params)
{
    json_t *request = make_request();
    json_t *params = json_object();
    json_object_set_new(request, "params", params);
    json_t *result = NULL;

    CHECK_EQUAL(1, read_resource(request, params, &result, NULL));
    CHECK(-32602 == json_integer_value(json_object_get(result, "code")));
    STRCMP_EQUAL("Invalid params", json_string_value(json_object_get(result, "message")));
    STRCMP_EQUAL("Key 'endpointName' missing", json_string_value(json_object_get(result, "data")));
    json_decref(request);
    json_decref(result);
    mock().checkExpectations();
}

TEST(edge_core_mgmt, read_resource_endpoint_name_empty)
{
    json_t *request = make_request();
    json_t *params = json_object();
    json_object_set_new(request, "params", params);
    json_t *endpoint_name = json_string("");
    json_object_set_new(params, "endpointName", endpoint_name);
    json_t *result = NULL;

    CHECK_EQUAL(1, read_resource(request, params, &result, NULL));
    CHECK(-32602 == json_integer_value(json_object_get(result, "code")));
    STRCMP_EQUAL("Invalid params", json_string_value(json_object_get(result, "message")));
    STRCMP_EQUAL("Value for key 'endpointName' missing or empty", json_string_value(json_object_get(result, "data")));
    json_decref(request);
    json_decref(result);
    mock().checkExpectations();
}

TEST(edge_core_mgmt, read_resource_endpoint_name_no_uri)
{
    json_t *request = make_request();
    json_t *params = json_object();
    json_object_set_new(request, "params", params);
    json_t *endpoint_name = json_string("sample_endpoint");
    json_object_set_new(params, "endpointName", endpoint_name);
    json_t *result = NULL;

    CHECK_EQUAL(1, read_resource(request, params, &result, NULL));
    CHECK(-32602 == json_integer_value(json_object_get(result, "code")));
    STRCMP_EQUAL("Invalid params", json_string_value(json_object_get(result, "message")));
    STRCMP_EQUAL("Key 'uri' missing", json_string_value(json_object_get(result, "data")));
    json_decref(request);
    json_decref(result);
    mock().checkExpectations();
}

TEST(edge_core_mgmt, read_resource_endpoint_name_empty_uri)
{
    json_t *request = make_request();
    json_t *params = json_object();
    json_object_set_new(request, "params", params);
    json_t *endpoint_name = json_string("sample_endpoint");
    json_object_set_new(params, "endpointName", endpoint_name);
    json_object_set_new(params, "uri", json_string(""));
    json_t *result = NULL;

    CHECK_EQUAL(1, read_resource(request, params, &result, NULL));
    CHECK(-32602 == json_integer_value(json_object_get(result, "code")));
    STRCMP_EQUAL("Invalid params", json_string_value(json_object_get(result, "message")));
    STRCMP_EQUAL("Value for key 'uri' missing or empty", json_string_value(json_object_get(result, "data")));
    json_decref(request);
    json_decref(result);
    mock().checkExpectations();
}

TEST(edge_core_mgmt, read_resource_endpoint_name_and_uri_ok)
{
    json_t *request = make_request();
    json_t *params = json_object();
    json_object_set_new(request, "params", params);
    json_t *endpoint_name = json_string("sample_endpoint");
    json_object_set_new(params, "endpointName", endpoint_name);
    json_t *uri = json_string("/1/2/3");
    json_object_set_new(params, "uri", uri);
    json_t *result = NULL;
    char *value = strdup("56.616138458");
    uint32_t value_len = 12;
    edgeclient_resource_attributes_t attributes;
    attributes.type = LWM2M_FLOAT;
    attributes.operations_allowed = 1;

    mock().expectOneCall("get_resource_value_and_attributes")
            .withStringParameter("endpoint_name", "sample_endpoint")
            .withParameter("object_id", 1)
            .withParameter("object_instance_id", 2)
            .withParameter("resource_id", 3)
            .withOutputParameterReturning("attributes", &attributes, sizeof(edgeclient_resource_attributes_t))
            .withOutputParameterReturning("value", &value, sizeof(char *))
            .withOutputParameterReturning("value_length", &value_len, sizeof(uint32_t))
            .andReturnValue(true);
    int32_t rc = read_resource(request, params, &result, NULL);
    CHECK_EQUAL(0, rc);
    CHECK_EQUAL(0, json_integer_value(json_object_get(result, "code")));
    STRCMP_EQUAL("56.616138458", json_string_value(json_object_get(result, "stringValue")));
    STRCMP_EQUAL("QExO3Z//dX0=", json_string_value(json_object_get(result, "base64Value")));
    STRCMP_EQUAL("float", json_string_value(json_object_get(result, "type")));
    json_decref(request);
    json_decref(result);
    mock().checkExpectations();
}

TEST(edge_core_mgmt, read_resource_endpoint_name_and_uri_opaque)
{
    json_t *request = make_request();
    json_t *params = json_object();
    json_object_set_new(request, "params", params);
    json_t *endpoint_name = json_string("sample_endpoint");
    json_object_set_new(params, "endpointName", endpoint_name);
    json_t *uri = json_string("/1/2/3");
    json_object_set_new(params, "uri", uri);
    json_t *result = NULL;
    char *value = (char *) calloc(1, 12);
    value[1] = 1;
    value[11] = 1;

    uint32_t value_len = 12;
    edgeclient_resource_attributes_t attributes;
    attributes.type = LWM2M_OPAQUE;
    attributes.operations_allowed = 1;

    mock().expectOneCall("get_resource_value_and_attributes")
            .withStringParameter("endpoint_name", "sample_endpoint")
            .withParameter("object_id", 1)
            .withParameter("object_instance_id", 2)
            .withParameter("resource_id", 3)
            .withOutputParameterReturning("attributes", &attributes, sizeof(edgeclient_resource_attributes_t))
            .withOutputParameterReturning("value", &value, sizeof(char *))
            .withOutputParameterReturning("value_length", &value_len, sizeof(uint32_t))
            .andReturnValue(true);
    int32_t rc = read_resource(request, params, &result, NULL);
    CHECK_EQUAL(0, rc);
    CHECK_EQUAL(0, json_integer_value(json_object_get(result, "code")));
    // Opaque shouldn't have string value
    CHECK(NULL == json_object_get(result, "stringValue"));
    STRCMP_EQUAL("AAEAAAAAAAAAAAAB", json_string_value(json_object_get(result, "base64Value")));
    STRCMP_EQUAL("opaque", json_string_value(json_object_get(result, "type")));
    json_decref(request);
    json_decref(result);
    mock().checkExpectations();
}

static void test_malformed_uri(const char *malformed_uri)
{
    json_t *request = make_request();
    json_t *params = json_object();
    json_object_set_new(request, "params", params);
    json_t *endpoint_name = json_string("sample_endpoint");
    json_object_set_new(params, "endpointName", endpoint_name);
    json_t *uri = json_string(malformed_uri);
    json_object_set_new(params, "uri", uri);
    json_t *result = NULL;

    int32_t rc = read_resource(request, params, &result, NULL);
    CHECK_EQUAL(1, rc);
    CHECK(-32602 == json_integer_value(json_object_get(result, "code")));
    STRCMP_EQUAL("Invalid params", json_string_value(json_object_get(result, "message")));
    STRCMP_EQUAL("Value for key 'uri' is malformed", json_string_value(json_object_get(result, "data")));
    json_decref(request);
    json_decref(result);
    mock().checkExpectations();
}

TEST(edge_core_mgmt, read_resource_endpoint_name_and_uri_malformed)
{
    test_malformed_uri("/");
    test_malformed_uri("1/2/3");
    test_malformed_uri("/a/2/3");
    test_malformed_uri("/1/2/3/4");
    test_malformed_uri("1/2/3/");
    mock().checkExpectations();
}

TEST(edge_core_mgmt, read_resource_resource_not_found)
{
    json_t *request = make_request();
    json_t *params = json_object();
    json_object_set_new(request, "params", params);
    json_t *endpoint_name = json_string("sample_endpoint");
    json_object_set_new(params, "endpointName", endpoint_name);
    json_t *uri = json_string("/1/2/3");
    json_object_set_new(params, "uri", uri);
    json_t *result = NULL;
    char *value = NULL;
    uint32_t value_len = 0;
    edgeclient_resource_attributes_t attributes;
    attributes.type = LWM2M_FLOAT;
    attributes.operations_allowed = OPERATION_READ;

    mock().expectOneCall("get_resource_value_and_attributes")
            .withStringParameter("endpoint_name", "sample_endpoint")
            .withParameter("object_id", 1)
            .withParameter("object_instance_id", 2)
            .withParameter("resource_id", 3)
            .withOutputParameterReturning("attributes", &attributes, sizeof(edgeclient_resource_attributes_t))
            .withOutputParameterReturning("value", &value, sizeof(char *))
            .withOutputParameterReturning("value_length", &value_len, sizeof(uint32_t))
            .andReturnValue(false);
    int32_t rc = read_resource(request, params, &result, NULL);
    CHECK_EQUAL(1, rc);
    CHECK_EQUAL(-30102, json_integer_value(json_object_get(result, "code")));
    STRCMP_EQUAL("Resource not found.", json_string_value(json_object_get(result, "message")));
    STRCMP_EQUAL("Cannot read resource value", json_string_value(json_object_get(result, "data")));
    json_decref(request);
    json_decref(result);
    mock().checkExpectations();
}

TEST(edge_core_mgmt, read_resource_resource_not_readable)
{
    json_t *request = make_request();
    json_t *params = json_object();
    json_object_set_new(request, "params", params);
    json_t *endpoint_name = json_string("sample_endpoint");
    json_object_set_new(params, "endpointName", endpoint_name);
    json_t *uri = json_string("/1/2/3");
    json_object_set_new(params, "uri", uri);
    json_t *result = NULL;
    char *value = strdup("56.616138458");
    uint32_t value_len = 12;
    edgeclient_resource_attributes_t attributes;
    attributes.type = LWM2M_FLOAT;
    attributes.operations_allowed = OPERATION_EXECUTE;

    mock().expectOneCall("get_resource_value_and_attributes")
            .withStringParameter("endpoint_name", "sample_endpoint")
            .withParameter("object_id", 1)
            .withParameter("object_instance_id", 2)
            .withParameter("resource_id", 3)
            .withOutputParameterReturning("attributes", &attributes, sizeof(edgeclient_resource_attributes_t))
            .withOutputParameterReturning("value", &value, sizeof(char *))
            .withOutputParameterReturning("value_length", &value_len, sizeof(uint32_t))
            .andReturnValue(true);
    int32_t rc = read_resource(request, params, &result, NULL);
    CHECK_EQUAL(1, rc);
    CHECK_EQUAL(-30104, json_integer_value(json_object_get(result, "code")));
    STRCMP_EQUAL("Resource not readable.", json_string_value(json_object_get(result, "message")));
    STRCMP_EQUAL("Cannot read resource value", json_string_value(json_object_get(result, "data")));
    json_decref(request);
    json_decref(result);
    mock().checkExpectations();
}

TEST(edge_core_mgmt, write_resource_empty_endpoint)
{
    json_t *request = make_request();
    json_t *params = json_object();
    json_object_set_new(request, "params", params);
    json_t *result = NULL;
    json_t *endpoint_name = json_string("");
    json_object_set_new(params, "endpointName", endpoint_name);
    int32_t rc = write_resource(request, params, &result, NULL);
    CHECK_EQUAL(1, rc);
    CHECK(-32602 == json_integer_value(json_object_get(result, "code")));
    STRCMP_EQUAL("Invalid params", json_string_value(json_object_get(result, "message")));
    STRCMP_EQUAL("Value for key 'endpointName' missing or empty", json_string_value(json_object_get(result, "data")));
    json_decref(request);
    json_decref(result);
    mock().checkExpectations();
}

TEST(edge_core_mgmt, write_resource_no_uri)
{
    json_t *request = make_request();
    json_t *params = json_object();
    json_object_set_new(request, "params", params);
    json_t *result = NULL;
    json_t *endpoint_name = json_string("sample_endpoint");
    json_object_set_new(params, "endpointName", endpoint_name);
    int32_t rc = write_resource(request, params, &result, NULL);
    CHECK_EQUAL(1, rc);
    CHECK(-32602 == json_integer_value(json_object_get(result, "code")));
    STRCMP_EQUAL("Invalid params", json_string_value(json_object_get(result, "message")));
    STRCMP_EQUAL("Key 'uri' missing", json_string_value(json_object_get(result, "data")));
    json_decref(request);
    json_decref(result);
    mock().checkExpectations();
}

TEST(edge_core_mgmt, write_resource_empty_uri)
{
    json_t *request = make_request();
    json_t *params = json_object();
    json_object_set_new(request, "params", params);
    json_t *result = NULL;
    json_t *endpoint_name = json_string("sample_endpoint");
    json_object_set_new(params, "endpointName", endpoint_name);
    json_t *uri = json_string("");
    json_object_set_new(params, "uri", uri);
    int32_t rc = write_resource(request, params, &result, NULL);
    CHECK_EQUAL(1, rc);
    CHECK(-32602 == json_integer_value(json_object_get(result, "code")));
    STRCMP_EQUAL("Invalid params", json_string_value(json_object_get(result, "message")));
    STRCMP_EQUAL("Value for key 'uri' missing or empty", json_string_value(json_object_get(result, "data")));
    json_decref(request);
    json_decref(result);
    mock().checkExpectations();
}

TEST(edge_core_mgmt, write_resource_b64_value_key_missing)
{
    json_t *request = make_request();
    json_t *params = json_object();
    json_object_set_new(request, "params", params);
    json_t *result = NULL;
    json_t *endpoint_name = json_string("sample_endpoint");
    json_object_set_new(params, "endpointName", endpoint_name);
    json_t *uri = json_string("/1/2/3");
    json_object_set_new(params, "uri", uri);
    mock().expectOneCall("deallocate_request_context").withPointerParameter("request_context", NULL);
    int32_t rc = write_resource(request, params, &result, NULL);
    CHECK_EQUAL(1, rc);
    CHECK(-32602 == json_integer_value(json_object_get(result, "code")));
    STRCMP_EQUAL("Invalid params", json_string_value(json_object_get(result, "message")));
    STRCMP_EQUAL("Key 'base64Value' missing", json_string_value(json_object_get(result, "data")));
    json_decref(request);
    json_decref(result);
    mock().checkExpectations();
}

TEST(edge_core_mgmt, write_resource_b64_value_missing)
{
    json_t *request = make_request();
    json_t *params = json_object();
    json_object_set_new(request, "params", params);
    json_t *result = NULL;
    json_t *endpoint_name = json_string("sample_endpoint");
    json_object_set_new(params, "endpointName", endpoint_name);
    json_t *uri = json_string("/1/2/3");
    json_object_set_new(params, "uri", uri);
    json_object_set_new(params, "base64Value", json_null());
    mock().expectOneCall("deallocate_request_context").withPointerParameter("request_context", NULL);
    int32_t rc = write_resource(request, params, &result, NULL);
    CHECK_EQUAL(1, rc);
    CHECK(-32602 == json_integer_value(json_object_get(result, "code")));
    STRCMP_EQUAL("Invalid params", json_string_value(json_object_get(result, "message")));
    STRCMP_EQUAL("Value for key 'base64Value' missing", json_string_value(json_object_get(result, "data")));
    json_decref(request);
    json_decref(result);
    mock().checkExpectations();
}

TEST(edge_core_mgmt, write_resource_0_len_value)
{
    struct connection *mgmt_connection = (struct connection *) calloc(1, sizeof(struct connection));
    struct connection *pt_connection = (struct connection *) calloc(1, sizeof(struct connection));
    pt_connection->transport_connection = (transport_connection_t *) calloc(1, sizeof(transport_connection_t));
    pt_connection->transport_connection->write_function = mocked_pt_write_function;
    mgmt_connection->transport_connection = (transport_connection_t *) calloc(1, sizeof(transport_connection_t));
    mgmt_connection->transport_connection->write_function = mocked_mgmt_write_function;
    json_message_t *mgmt_userdata = (json_message_t *) malloc(sizeof(json_message_t));
    mgmt_userdata->connection = mgmt_connection;

    mock().expectOneCall("get_endpoint_context")
            .withStringParameter("endpoint_name", "sample_endpoint")
            .withOutputParameterReturning("context_out", &pt_connection, sizeof(struct connection *))
            .andReturnValue(true);

    edgeclient_resource_attributes_t attributes;
    attributes.operations_allowed = OPERATION_WRITE;
    attributes.type = LWM2M_FLOAT;
    mock().expectOneCall("get_resource_attributes")
            .withStringParameter("endpoint_name", "sample_endpoint")
            .withUnsignedIntParameter("object_id", 1)
            .withUnsignedIntParameter("object_instance_id", 2)
            .withUnsignedIntParameter("resource_id", 3)
            .withOutputParameterReturning("attributes_out", &attributes, sizeof(edgeclient_resource_attributes_t))
            .andReturnValue(true);

    uint32_t value_length = 0;
    uint32_t token_len = 0;
    ValuePointer token_pointer(NULL, 0);
    ValuePointer value_pointer((const uint8_t *) "", 0);
    mock().expectOneCall("edgeclient_verify_value")
            .withIntParameter("resource_type", LWM2M_FLOAT)
            .withParameterOfType("ValuePointer", "value", (const void *) &value_pointer)
            .withUnsignedIntParameter("value_length", value_length)
            .andReturnValue(true);

    edgeclient_request_context_t *request_context = (edgeclient_request_context_t *)
            calloc(1, sizeof(edgeclient_request_context_t));
    request_context->device_id = strdup("sample_endpoint");
    request_context->object_id = 1;
    request_context->object_instance_id = 2;
    request_context->resource_id = 3;
    request_context->success_handler = mgmt_api_write_success;
    request_context->failure_handler = mgmt_api_write_failure;
    request_context->value_len = 0;
    request_context->value = (uint8_t *) "";
    request_context->operation = OPERATION_WRITE;
    mock().expectOneCall("allocate_request_context")
            .withStringParameter("uri", "d/sample_endpoint/1/2/3")
            .withParameterOfType("ValuePointer", "value", (void *) &value_pointer)
            .withUnsignedIntParameter("value_length", value_length)
            .withParameterOfType("ValuePointer", "token", (void *) &token_pointer)
            .withUnsignedIntParameter("token_len", token_len)
            .withIntParameter("value_format", EDGECLIENT_VALUE_IN_BINARY)
            .withUnsignedIntParameter("operation", OPERATION_WRITE)
            .withIntParameter("resource_type", LWM2M_FLOAT)
            .withPointerParameter("success_handler", (void *) mgmt_api_write_success)
            .withPointerParameter("failure_handler", (void *) mgmt_api_write_failure)
            .andReturnValue(request_context);

    json_t *request = make_request();
    json_t *params = json_object();
    json_object_set_new(request, "params", params);
    json_t *result = NULL;
    json_t *endpoint_name = json_string("sample_endpoint");
    json_object_set_new(params, "endpointName", endpoint_name);
    json_t *uri = json_string("/1/2/3");
    json_object_set_new(params, "uri", uri);
    json_object_set_new(params, "base64Value", json_string(""));

    mock().expectOneCall("deallocate_request_context").withPointerParameter("request_context", request_context);

    int32_t rc = write_resource(request, params, &result, mgmt_userdata);
    CHECK_EQUAL(1, rc);
    CHECK(-30101 == json_integer_value(json_object_get(result, "code")));
    STRCMP_EQUAL("Illegal value.", json_string_value(json_object_get(result, "message")));
    STRCMP_EQUAL("Cannot write resource value", json_string_value(json_object_get(result, "data")));

    json_decref(request);
    json_decref(result);
    free(request_context->device_id);
    free(request_context);
    free(mgmt_userdata);
    free(mgmt_connection->transport_connection);
    free(mgmt_connection);
    free(pt_connection->transport_connection);
    free(pt_connection);
    mock().checkExpectations();
}

static edgeclient_request_context_t *allocate_fake_request_context()
{
    edgeclient_request_context_t *request_context = (edgeclient_request_context_t *)
            calloc(1, sizeof(edgeclient_request_context_t));
    request_context->device_id = strdup("sample_endpoint");
    request_context->object_id = 1;
    request_context->object_instance_id = 2;
    request_context->resource_id = 3;
    request_context->success_handler = mgmt_api_write_success;
    request_context->failure_handler = mgmt_api_write_failure;
    request_context->value_len = 8;
    request_context->value = (uint8_t *) strdup("\x40\x4c\x4e\xdd\x9f\xff\x75\x7d");
    return request_context;
}

static void deallocate_fake_request_context(edgeclient_request_context_t *request_context)
{
    free(request_context->device_id);
    free(request_context->value);
    free(request_context);
}

static int mocked_pt_write_function(struct connection *connection, char *data, size_t len)
{
    ValuePointer *value_pointer = new ValuePointer((uint8_t *) data, len);
    int ret = mock().actualCall("mocked_pt_write_function")
                      .withPointerParameter("connection", connection)
                      .withParameterOfType("ValuePointer", "data", value_pointer)
                      .returnIntValue();
    delete value_pointer;
    // We can do this here. Normally it frees it in the LWS Write call-back.
    free(data);
    return ret;
}

static int mocked_mgmt_write_function(struct connection *connection, char *data, size_t len)
{
    ValuePointer *value_pointer = new ValuePointer((uint8_t *) data, len);
    int ret = mock().actualCall("mocked_mgmt_write_function")
                      .withPointerParameter("connection", connection)
                      .withParameterOfType("ValuePointer", "data", value_pointer)
                      .returnIntValue();
    delete value_pointer;
    // We can do this here. Normally it frees it in the LWS Write call-back.
    free(data);
    return ret;
}


static void test_write_resource(bool endpoint_found,
                                bool resource_found,
                                bool resource_writable,
                                bool pt_write_succeeds,
                                bool update_resource_succeeds,
                                bool mgmt_response_write_function_succeeds)
{
    edgeclient_resource_attributes_t attributes;
    json_t *request = make_request();
    json_t *params = json_object();
    json_t *result = NULL;
    json_object_set_new(request, "params", params);
    json_t *endpoint_name = json_string("sample_endpoint");
    json_object_set_new(params, "endpointName", endpoint_name);
    json_t *uri = json_string("/1/2/3");
    json_object_set_new(params, "uri", uri);
    json_t *base64_value = json_string("QExO3Z//dX0=");
    json_object_set_new(params, "base64Value", base64_value);
    uint32_t value_length = 8;
    struct connection *mgmt_connection = (struct connection *) calloc(1, sizeof(struct connection));
    struct connection *pt_connection = (struct connection *) calloc(1, sizeof(struct connection));
    pt_connection->transport_connection = (transport_connection_t *) calloc(1, sizeof(transport_connection_t));
    pt_connection->transport_connection->write_function = mocked_pt_write_function;
    mgmt_connection->transport_connection = (transport_connection_t *) calloc(1, sizeof(transport_connection_t));
    mgmt_connection->transport_connection->write_function = mocked_mgmt_write_function;

    json_message_t *mgmt_userdata = (json_message_t *) malloc(sizeof(json_message_t));
    mgmt_userdata->connection = mgmt_connection;
    ValuePointer value_pointer((const uint8_t *) "\x040\x04c\x04e\x0dd\x09f\x0ff\x075\x07d", 8);
    mock().expectOneCall("get_endpoint_context")
            .withStringParameter("endpoint_name", "sample_endpoint")
            .withOutputParameterReturning("context_out", &pt_connection, sizeof(struct connection *))
            .andReturnValue(endpoint_found);
    if (endpoint_found) {
        memset(&attributes, 0, sizeof(edgeclient_resource_attributes_t));
        if (resource_writable) {
            attributes.operations_allowed = OPERATION_WRITE;
        }
        attributes.type = LWM2M_FLOAT;
        mock().expectOneCall("get_resource_attributes")
                .withStringParameter("endpoint_name", "sample_endpoint")
                .withUnsignedIntParameter("object_id", 1)
                .withUnsignedIntParameter("object_instance_id", 2)
                .withUnsignedIntParameter("resource_id", 3)
                .withOutputParameterReturning("attributes_out", &attributes, sizeof(edgeclient_resource_attributes_t))
                .andReturnValue(resource_found);
    }
    edgeclient_request_context_t *request_context;
    ValuePointer *write_to_pt_value;
    uint32_t token_len = 0;
    ValuePointer token_pointer(NULL, 0);
    if (resource_found && resource_writable && endpoint_found) {
        mock().expectOneCall("edgeclient_verify_value")
                .withIntParameter("resource_type", LWM2M_FLOAT)
                .withParameterOfType("ValuePointer", "value", (const void *) &value_pointer)
                .withUnsignedIntParameter("value_length", value_length)
                .andReturnValue(true);
        request_context = allocate_fake_request_context();
        mock().expectOneCall("allocate_request_context")
                .withStringParameter("uri", "d/sample_endpoint/1/2/3")
                .withParameterOfType("ValuePointer", "value", (void *) &value_pointer)
                .withUnsignedIntParameter("value_length", value_length)
                .withParameterOfType("ValuePointer", "token", (void *) &token_pointer)
                .withUnsignedIntParameter("token_len", token_len)
                .withIntParameter("value_format", EDGECLIENT_VALUE_IN_BINARY)
                .withUnsignedIntParameter("operation", OPERATION_WRITE)
                .withIntParameter("resource_type", LWM2M_FLOAT)
                .withPointerParameter("success_handler", (void *) mgmt_api_write_success)
                .withPointerParameter("failure_handler", (void *) mgmt_api_write_failure)
                .andReturnValue(request_context);
        write_to_pt_value = new ValuePointer((const uint8_t
                                                      *) "{\"id\":\"314159\",\"jsonrpc\":\"2.0\",\"method\":\"write\","
                                                         "\"params\":{\"operation\":0,"
                                                         "\"uri\":{\"deviceId\":\"sample_endpoint\",\"objectId\":"
                                                         "1,\"objectInstanceId\":2,"
                                                         "\"resourceId\":3},\"value\":\"QExO3Z//dX0=\"}}",
                                             182);
        mock().expectOneCall("mocked_pt_write_function")
                .withPointerParameter("connection", pt_connection)
                .withParameterOfType("ValuePointer", "data", write_to_pt_value);
    }

    if (!resource_found || !resource_writable || !endpoint_found) {
        mock().expectOneCall("deallocate_request_context").withPointerParameter("request_context", NULL);
    } else {
        expect_mutexing();
    }

    int32_t rc = write_resource(request, params, &result, mgmt_userdata);

    if (!resource_found || !resource_writable || !endpoint_found) {
        CHECK(1 == rc);
        if (!resource_writable && endpoint_found) {
            CHECK(-30105 == json_integer_value(json_object_get(result, "code")));
            CHECK(!strcmp("Resource not writable.", json_string_value(json_object_get(result, "message"))));
        }
        if (!resource_found || !endpoint_found) {
            CHECK(-30102 == json_integer_value(json_object_get(result, "code")));
            CHECK(!strcmp("Resource not found.", json_string_value(json_object_get(result, "message"))));
        }
        CHECK(!strcmp("Cannot write resource value", json_string_value(json_object_get(result, "data"))));
    } else {
        CHECK(-1 == rc);
        CHECK(NULL == result);
        pt_api_result_code_e update_ret_val = PT_API_SUCCESS;
        if (!update_resource_succeeds) {
            update_ret_val = PT_API_INTERNAL_ERROR;
        }
        if (pt_write_succeeds) {
            mock().expectOneCall("update_resource_value")
                    .withStringParameter("endpoint_name", "sample_endpoint")
                    .withUnsignedIntParameter("object_id", 1)
                    .withUnsignedIntParameter("object_instance_id", 2)
                    .withUnsignedIntParameter("resource_id", 3)
                    .withParameterOfType("ValuePointer", "value", (const void *) &value_pointer)
                    .withUnsignedIntParameter("value_length", value_length)
                    .andReturnValue((int32_t) update_ret_val);
        }
        ValuePointer *mgmt_ok_response_value = new ValuePointer(
                (const uint8_t *) "{\"id\":\"123\",\"jsonrpc\":\"2.0\",\"result\":\"ok\"}", 42);
        ValuePointer *mgmt_failure_response_value = new ValuePointer((const uint8_t *) "{\"error\":{\"code\":-30106,"
                                                                                       "\"data\":\"Cannot write "
                                                                                       "resource "
                                                                                       "value\",\"message\":\"Write "
                                                                                       "request to protocol translator "
                                                                                       "failed.\"},\"id\":\"123\","
                                                                                       "\"jsonrpc\":\"2.0\"}",
                                                                     146);
        ValuePointer
                *mgmt_cannot_write = new ValuePointer((const uint8_t *) "{\"error\":{\"code\":-30000,\"data\":\"Cannot "
                                                                        "write resource value\",\"message\":\"Protocol "
                                                                        "translator API internal "
                                                                        "error.\"},\"id\":\"123\",\"jsonrpc\":\"2.0\"}",
                                                      141);
        ValuePointer *mgmt_response_value;
        if (pt_write_succeeds) {
            if (update_resource_succeeds) {
                mgmt_response_value = mgmt_ok_response_value;
            } else {
                mgmt_response_value = mgmt_cannot_write;
            }
        } else {
            mgmt_response_value = mgmt_failure_response_value;
        }
        mock().expectOneCall("mocked_mgmt_write_function")
                .withPointerParameter("connection", mgmt_connection)
                .withParameterOfType("ValuePointer", "data", mgmt_response_value)
                .andReturnValue(mgmt_response_write_function_succeeds ? 0 : 1);
        mock().expectOneCall("deallocate_request_context").withPointerParameter("request_context", request_context);
        if (pt_write_succeeds) {
            mgmt_api_write_success(request_context);
        } else {
            mgmt_api_write_failure(request_context);
        }
        deallocate_fake_request_context(request_context);
        delete write_to_pt_value;
        delete mgmt_ok_response_value;
        delete mgmt_cannot_write;
        delete mgmt_failure_response_value;
    }
    json_decref(request);
    json_decref(result);
    free(mgmt_userdata);
    free(mgmt_connection->transport_connection);
    free(mgmt_connection);
    free(pt_connection->transport_connection);
    free(pt_connection);
    mock().checkExpectations();
}

TEST(edge_core_mgmt, write_resource_value_ok)
{
    test_write_resource(true, /* endpoint_found */
                        true, /* resource_found */
                        true, /* resource writable */
                        true, /* pt_write_succeeds */
                        true, /* update_resource_succeeds */
                        true /* mgmt_response_write_function_succeeds */);
}

TEST(edge_core_mgmt, write_resource_endpoint_not_found)
{
    test_write_resource(false, /* endpoint_found */
                        false, /* resource_found */
                        false, /* resource writable */
                        false, /* pt_write_succeeds */
                        false, /* update_resource_succeeds */
                        true /* mgmt_response_write_function_succeeds */);
}

TEST(edge_core_mgmt, write_resource_resource_not_found)
{
    test_write_resource(true,  /* endpoint_found */
                        false, /* resource_found */
                        true,  /* resource writable */
                        true,  /* pt_write_succeeds */
                        true,  /* update_resource_succeeds */
                        true /* mgmt_response_write_function_succeeds */);
}

TEST(edge_core_mgmt, write_resource_resource_not_writable)
{
    test_write_resource(true,  /* endpoint_found */
                        true,  /* resource_found */
                        false, /* resource writable */
                        true,  /* pt_write_succeeds */
                        true,  /* update_resource_succeeds */
                        true /* mgmt_response_write_function_succeeds */);
}

TEST(edge_core_mgmt, write_resource_pt_write_fails)
{
    test_write_resource(true,  /* endpoint_found */
                        true,  /* resource_found */
                        true,  /* resource writable */
                        false, /* pt_write_succeeds */
                        true,  /* update_resource_succeeds */
                        true /* mgmt_response_write_function_succeeds */);
}

TEST(edge_core_mgmt, write_resource_update_resource_fails)
{
    test_write_resource(true,  /* endpoint_found */
                        true,  /* resource_found */
                        true,  /* resource writable */
                        true,  /* pt_write_succeeds */
                        false, /* update_resource_succeeds */
                        true /* mgmt_response_write_function_succeeds */);
}

TEST(edge_core_mgmt, write_resource_mgmt_response_write_function_fails)
{
    test_write_resource(true, /* endpoint_found */
                        true, /* resource_found */
                        true, /* resource writable */
                        true, /* pt_write_succeeds */
                        true, /* update_resource_succeeds */
                        false /* mgmt_response_write_function_succeeds */);
}

TEST(edge_core_mgmt, write_resource_value_invalid)
{
    json_t *request = make_request();
    json_t *params = json_object();
    json_object_set_new(request, "params", params);
    json_t *result = NULL;
    json_t *endpoint_name = json_string("sample_endpoint");
    json_object_set_new(params, "endpointName", endpoint_name);
    json_t *uri = json_string("/1/2/3");
    json_object_set_new(params, "uri", uri);
    json_t *base64_value = json_string("QExO3Z//dQ==");
    json_object_set_new(params, "base64Value", base64_value);
    uint32_t value_length = 7;
    edgeclient_resource_attributes_t attributes;
    attributes.operations_allowed = OPERATION_WRITE;
    attributes.type = LWM2M_FLOAT;
    ValuePointer value_pointer((const uint8_t *) "\x040\x04c\x04e\x0dd\x09f\x0ff\x075", 7);
    void *pt_connection;
    mock().expectOneCall("get_endpoint_context")
            .withStringParameter("endpoint_name", "sample_endpoint")
            .withOutputParameterReturning("context_out", &pt_connection, sizeof(struct connection *))
            .andReturnValue(true);
    mock().expectOneCall("get_resource_attributes")
            .withStringParameter("endpoint_name", "sample_endpoint")
            .withUnsignedIntParameter("object_id", 1)
            .withUnsignedIntParameter("object_instance_id", 2)
            .withUnsignedIntParameter("resource_id", 3)
            .withOutputParameterReturning("attributes_out", &attributes, sizeof(edgeclient_resource_attributes_t))
            .andReturnValue(true);
    mock().expectOneCall("edgeclient_verify_value")
            .withIntParameter("resource_type", LWM2M_FLOAT)
            .withParameterOfType("ValuePointer", "value", (const void *) &value_pointer)
            .withUnsignedIntParameter("value_length", value_length)
            .andReturnValue(false);
    mock().expectOneCall("deallocate_request_context").withPointerParameter("request_context", NULL);
    int32_t rc = write_resource(request, params, &result, NULL);
    CHECK(1 == rc);
    CHECK(-30101 == json_integer_value(json_object_get(result, "code")));
    STRCMP_EQUAL("Illegal value.", json_string_value(json_object_get(result, "message")));
    STRCMP_EQUAL("Cannot write resource value", json_string_value(json_object_get(result, "data")));
    json_decref(request);
    json_decref(result);
    mock().checkExpectations();
}
