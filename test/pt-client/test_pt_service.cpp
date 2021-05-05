#include "CppUTest/TestHarness.h"
#include "CppUTestExt/MockSupport.h"

#include "cpputest-custom-types/value_pointer.h"

extern "C" {
#include "jansson.h"
#include <string.h>
#include "pt-client/pt_api.h"
#include "pt-client/pt_api_internal.h"
#include "pt-client/client.h"
#include "common/constants.h"
#include "common/pt_api_error_codes.h"
}

struct test_context {
    struct context *context;
    struct connection *connection;
    protocol_translator_callbacks_t *pt_cbs;
};

#define TEST_VALUE     "test-value"
#define TEST_VALUE_B64 "dGVzdC12YWx1ZQ=="

TEST_GROUP(pt_service_api) {
    void setup()
    {
    }

    void teardown()
    {
        mock().checkExpectations();
    }
};

static int test_write_handler(struct connection *connection,
                              const char *device_id, const uint16_t object_id,
                              const uint16_t instance_id,
                              const uint16_t resource_id,
                              const unsigned int operation,
                              const uint8_t *value, const uint32_t value_size,
                              void *userdata)
{
    ValuePointer value_pointer = ValuePointer(value, value_size);
    return mock()
        .actualCall("test_write_handler")
        .withPointerParameter("connection", connection)
        .withStringParameter("device_id", device_id)
        .withIntParameter("object_id", object_id)
        .withIntParameter("instance_id", instance_id)
        .withIntParameter("resource_id", resource_id)
        .withIntParameter("operation", operation)
        .withParameterOfType("ValuePointer", "value", (const void*) &value_pointer)
        .withLongIntParameter("value_size", value_size)
        .withPointerParameter("userdata", userdata)
        .returnIntValue();
}

struct test_context* connection_initialized(const char *userdata)
{
    struct context *context = (struct context*) calloc(1, sizeof(struct context));
    client_data_t *client_data =
        (client_data_t*) malloc(sizeof(client_data_t));
    client_data->name = strdup("test-translator");

    protocol_translator_callbacks_t *pt_cbs = (protocol_translator_callbacks_t*) malloc(sizeof(protocol_translator_callbacks_t));
    pt_cbs->connection_ready_cb = NULL;
    pt_cbs->connection_shutdown_cb = NULL;
    pt_cbs->received_write_cb = test_write_handler;

    struct connection *connection = connection_init(context, client_data,
                                                    pt_cbs, (void*) userdata);

    struct test_context *test_ctx = (struct test_context*)calloc(1, sizeof(struct test_context));
    test_ctx->context = context;
    test_ctx->connection = connection;
    test_ctx->pt_cbs = pt_cbs;
    return test_ctx;
}

static void free_test_context(struct test_context *test_context)
{
    free(test_context->context);
    free(test_context->connection->client_data->name);
    free(test_context->connection->client_data);
    free(test_context->connection);
    free(test_context->pt_cbs);
    free(test_context);
}

static void check_error(json_t *result, const int error_code, const char* error_msg)
{
    CHECK(NULL != result);
    json_t *integer_handle = json_object_get(result, "code");
    json_t *message_handle = json_object_get(result, "message");
    CHECK_EQUAL(error_code, json_integer_value(integer_handle));
    STRNCMP_EQUAL(error_msg, json_string_value(message_handle), strlen(error_msg));
}

TEST(pt_service_api, test_receive_write_value_no_request_id)
{
    const char *userdata =  "dummy_userdata";
    struct test_context *t_ctx = connection_initialized(userdata);
    json_t *request = json_object();
    json_object_set_new(request, "jsonrpc", json_string("2.0"));
    json_object_set_new(request, "method", json_string("write"));

    char* data = json_dumps(request, JSON_COMPACT | JSON_SORT_KEYS);
    struct json_message_t *msg = alloc_json_message_t(data, strlen(data), t_ctx->connection);
    free(data);

    json_t *params = NULL;
    json_t *result = NULL;
    CHECK_EQUAL(1, pt_receive_write_value(request, params, &result, msg));

    check_error(result, JSONRPC_INVALID_PARAMS, "Invalid params. Missing 'id'-field from request.");
    deallocate_json_message_t(msg);
    free_test_context(t_ctx);
    json_decref(request);
    json_decref(result);
}

TEST(pt_service_api, test_receive_write_value_no_params_element)
{
    const char *userdata = "dummy_userdata";
    struct test_context *t_ctx = connection_initialized(userdata);
    json_t *request = json_object();
    json_object_set_new(request, "jsonrpc", json_string("2.0"));
    json_object_set_new(request, "method", json_string("write"));
    json_object_set_new(request, "id", json_integer(1));

    char* data = json_dumps(request, JSON_COMPACT | JSON_SORT_KEYS);
    struct json_message_t *msg = alloc_json_message_t(data, strlen(data), t_ctx->connection);
    free(data);

    json_t *params = NULL;
    json_t *result = NULL;
    CHECK_EQUAL(1, pt_receive_write_value(request, params, &result, msg));

    check_error(result, JSONRPC_INVALID_PARAMS, "Invalid params. Missing 'params'-field from request.");
    deallocate_json_message_t(msg);
    free_test_context(t_ctx);
    json_decref(request);
    json_decref(result);
}

TEST(pt_service_api, test_receive_write_value_no_uri_element)
{
    const char *userdata = "dummy_userdata";
    struct test_context *t_ctx = connection_initialized(userdata);
    json_t *request = json_object();
    json_object_set_new(request, "jsonrpc", json_string("2.0"));
    json_object_set_new(request, "method", json_string("write"));
    json_object_set_new(request, "id", json_integer(1));

    json_t *params = json_object();
    json_object_set_new(request, "params", params);

    char* data = json_dumps(request, JSON_COMPACT | JSON_SORT_KEYS);
    struct json_message_t *msg = alloc_json_message_t(data, strlen(data), t_ctx->connection);
    free(data);

    json_t *result = NULL;

    CHECK_EQUAL(1, pt_receive_write_value(request, params, &result, msg));

    check_error(result, JSONRPC_INVALID_PARAMS, "Invalid params. Missing 'uri'-field.");
    deallocate_json_message_t(msg);
    free_test_context(t_ctx);
    json_decref(request);
    json_decref(result);
}

TEST(pt_service_api, test_receive_write_value_no_device_id)
{
    const char *userdata = "dummy_userdata";
    struct test_context *t_ctx = connection_initialized(userdata);
    json_t *request = json_object();
    json_object_set_new(request, "jsonrpc", json_string("2.0"));
    json_object_set_new(request, "method", json_string("write"));
    json_object_set_new(request, "id", json_integer(1));

    json_t *params = json_object();
    json_object_set_new(request, "params", params);

    json_t *uri = json_object();
    json_object_set_new(params, "uri", uri);

    char* data = json_dumps(request, JSON_COMPACT | JSON_SORT_KEYS);
    struct json_message_t *msg = alloc_json_message_t(data, strlen(data), t_ctx->connection);
    free(data);

    json_t *result = NULL;

    CHECK_EQUAL(1, pt_receive_write_value(request, params, &result, msg));

    check_error(result, JSONRPC_INVALID_PARAMS, "Invalid params. Missing 'deviceId'-field.");
    deallocate_json_message_t(msg);
    free_test_context(t_ctx);
    json_decref(request);
    json_decref(result);
}

TEST(pt_service_api, test_receive_write_value_no_object_id)
{
    const char *userdata = "dummy_userdata";
    struct test_context *t_ctx = connection_initialized(userdata);
    json_t *request = json_object();
    json_object_set_new(request, "jsonrpc", json_string("2.0"));
    json_object_set_new(request, "method", json_string("write"));
    json_object_set_new(request, "id", json_integer(1));

    json_t *params = json_object();
    json_object_set_new(request, "params", params);

    json_t *uri = json_object();
    json_object_set_new(params, "uri", uri);
    json_object_set_new(uri, "deviceId", json_string("test-device"));

    char* data = json_dumps(request, JSON_COMPACT | JSON_SORT_KEYS);
    struct json_message_t *msg = alloc_json_message_t(data, strlen(data), t_ctx->connection);
    free(data);
    json_t *result = NULL;

    CHECK_EQUAL(1, pt_receive_write_value(request, params, &result, msg));

    check_error(result, JSONRPC_INVALID_PARAMS, "Invalid params. Missing 'objectId'-field.");
    deallocate_json_message_t(msg);
    free_test_context(t_ctx);
    json_decref(request);
    json_decref(result);
}

TEST(pt_service_api, test_receive_write_value_no_object_instance_id)
{
    const char *userdata = "dummy_userdata";
    struct test_context *t_ctx = connection_initialized(userdata);
    json_t *request = json_object();
    json_object_set_new(request, "jsonrpc", json_string("2.0"));
    json_object_set_new(request, "method", json_string("write"));
    json_object_set_new(request, "id", json_integer(1));

    json_t *params = json_object();
    json_object_set_new(request, "params", params);

    json_t *uri = json_object();
    json_object_set_new(params, "uri", uri);
    json_object_set_new(uri, "deviceId", json_string("test-device"));
    json_object_set_new(uri, "objectId", json_integer(3303));

    char* data = json_dumps(request, JSON_COMPACT | JSON_SORT_KEYS);
    struct json_message_t *msg = alloc_json_message_t(data, strlen(data), t_ctx->connection);
    free(data);
    json_t *result = NULL;

    CHECK_EQUAL(1, pt_receive_write_value(request, params, &result, msg));

    check_error(result, JSONRPC_INVALID_PARAMS, "Invalid params. Missing 'objectInstanceId'-field.");
    deallocate_json_message_t(msg);
    free_test_context(t_ctx);
    json_decref(request);
    json_decref(result);
}

TEST(pt_service_api, test_receive_write_value_no_resource_id)
{
    const char *userdata = "dummy_userdata";
    struct test_context *t_ctx = connection_initialized(userdata);
    json_t *request = json_object();
    json_object_set_new(request, "jsonrpc", json_string("2.0"));
    json_object_set_new(request, "method", json_string("write"));
    json_object_set_new(request, "id", json_integer(1));

    json_t *params = json_object();
    json_object_set_new(request, "params", params);

    json_t *uri = json_object();
    json_object_set_new(params, "uri", uri);
    json_object_set_new(uri, "deviceId", json_string("test-device"));
    json_object_set_new(uri, "objectId", json_integer(3303));
    json_object_set_new(uri, "objectInstanceId", json_integer(0));

    char* data = json_dumps(request, JSON_COMPACT | JSON_SORT_KEYS);
    struct json_message_t *msg = alloc_json_message_t(data, strlen(data), t_ctx->connection);
    free(data);
    json_t *result = NULL;

    CHECK_EQUAL(1, pt_receive_write_value(request, params, &result, msg));

    check_error(result, JSONRPC_INVALID_PARAMS, "Invalid params. Missing 'resourceId'-field.");
    deallocate_json_message_t(msg);
    free_test_context(t_ctx);
    json_decref(request);
    json_decref(result);
}

TEST(pt_service_api, test_receive_write_value_no_value)
{
    const char *userdata = "dummy_userdata";
    struct test_context *t_ctx = connection_initialized(userdata);
    json_t *request = json_object();
    json_object_set_new(request, "jsonrpc", json_string("2.0"));
    json_object_set_new(request, "method", json_string("write"));
    json_object_set_new(request, "id", json_integer(1));

    json_t *params = json_object();
    json_object_set_new(request, "params", params);

    json_t *uri = json_object();
    json_object_set_new(params, "uri", uri);
    json_object_set_new(uri, "deviceId", json_string("test-device"));
    json_object_set_new(uri, "objectId", json_integer(3303));
    json_object_set_new(uri, "objectInstanceId", json_integer(0));
    json_object_set_new(uri, "resourceId", json_integer(5700));

    char* data = json_dumps(request, JSON_COMPACT | JSON_SORT_KEYS);
    struct json_message_t *msg = alloc_json_message_t(data, strlen(data), t_ctx->connection);
    free(data);
    json_t *result = NULL;

    CHECK_EQUAL(1, pt_receive_write_value(request, params, &result, msg));

    check_error(result, JSONRPC_INVALID_PARAMS, "Invalid params. Missing 'value'-field.");
    deallocate_json_message_t(msg);
    free_test_context(t_ctx);
    json_decref(request);
    json_decref(result);
}

TEST(pt_service_api, test_receive_write_value_no_operation)
{
    const char *userdata = "dummy_userdata";
    struct test_context *t_ctx = connection_initialized(userdata);
    json_t *request = json_object();
    json_object_set_new(request, "jsonrpc", json_string("2.0"));
    json_object_set_new(request, "method", json_string("write"));
    json_object_set_new(request, "id", json_integer(1));

    json_t *params = json_object();
    json_object_set_new(request, "params", params);
    json_object_set_new(params, "value", json_string(TEST_VALUE_B64));

    json_t *uri = json_object();
    json_object_set_new(params, "uri", uri);
    json_object_set_new(uri, "deviceId", json_string("test-device"));
    json_object_set_new(uri, "objectId", json_integer(3303));
    json_object_set_new(uri, "objectInstanceId", json_integer(0));
    json_object_set_new(uri, "resourceId", json_integer(5700));

    char* data = json_dumps(request, JSON_COMPACT | JSON_SORT_KEYS);
    struct json_message_t *msg = alloc_json_message_t(data, strlen(data), t_ctx->connection);
    free(data);
    json_t *result = NULL;

    CHECK_EQUAL(1, pt_receive_write_value(request, params, &result, msg));

    check_error(result, JSONRPC_INVALID_PARAMS, "Invalid params. Missing 'operation'-field.");
    deallocate_json_message_t(msg);
    free_test_context(t_ctx);
    json_decref(request);
    json_decref(result);
}

TEST(pt_service_api, test_receive_write_value_all_fields_ok_success_on_write_execute_no_data)
{
    const char *userdata = "dummy_userdata";
    const char *empty_string = "";
    struct test_context *t_ctx = connection_initialized(userdata);

    json_t *request = json_object();
    json_object_set_new(request, "jsonrpc", json_string("2.0"));
    json_object_set_new(request, "method", json_string("write"));
    json_object_set_new(request, "id", json_integer(1));

    json_t *params = json_object();
    json_object_set_new(request, "params", params);
    json_object_set_new(params, "value", json_string(empty_string));
    json_object_set_new(params, "operation", json_integer(OPERATION_EXECUTE));

    json_t *uri = json_object();
    json_object_set_new(params, "uri", uri);
    json_object_set_new(uri, "deviceId", json_string("test-device"));
    json_object_set_new(uri, "objectId", json_integer(3303));
    json_object_set_new(uri, "objectInstanceId", json_integer(0));
    json_object_set_new(uri, "resourceId", json_integer(5700));

    char *data = json_dumps(request, JSON_COMPACT | JSON_SORT_KEYS);
    struct json_message_t *msg = alloc_json_message_t(data, strlen(data), t_ctx->connection);
    free(data);
    json_t *result = NULL;

    ValuePointer value_pointer = ValuePointer((const uint8_t *) empty_string, 0);
    char *userdata_pointer = strdup("dummy_userdata");
    mock().expectOneCall("test_write_handler")
            .withPointerParameter("connection", t_ctx->connection)
            .withStringParameter("device_id", "test-device")
            .withIntParameter("object_id", 3303)
            .withIntParameter("instance_id", 0)
            .withIntParameter("resource_id", 5700)
            .withIntParameter("operation", OPERATION_EXECUTE)
            .withParameterOfType("ValuePointer", "value", (const void *) &value_pointer)
            .withLongIntParameter("value_size", 0)
            .withPointerParameter("userdata", t_ctx->connection->userdata)
            .andReturnValue(0);

    int rc = pt_receive_write_value(request, params, &result, msg);
    CHECK_EQUAL(0, rc);
    STRNCMP_EQUAL("ok", json_string_value(result), strlen("ok"));

    mock().checkExpectations();

    deallocate_json_message_t(msg);
    free(userdata_pointer);
    free_test_context(t_ctx);
    json_decref(request);
    json_decref(result);
}

TEST(pt_service_api, test_receive_write_value_all_fields_ok_success_on_write)
{
    const char *userdata = "dummy_userdata";
    struct test_context *t_ctx = connection_initialized(userdata);

    json_t *request = json_object();
    json_object_set_new(request, "jsonrpc", json_string("2.0"));
    json_object_set_new(request, "method", json_string("write"));
    json_object_set_new(request, "id", json_integer(1));

    json_t *params = json_object();
    json_object_set_new(request, "params", params);
    json_object_set_new(params, "value", json_string(TEST_VALUE_B64));
    json_object_set_new(params, "operation", json_integer(OPERATION_READ));

    json_t *uri = json_object();
    json_object_set_new(params, "uri", uri);
    json_object_set_new(uri, "deviceId", json_string("test-device"));
    json_object_set_new(uri, "objectId", json_integer(3303));
    json_object_set_new(uri, "objectInstanceId", json_integer(0));
    json_object_set_new(uri, "resourceId", json_integer(5700));

    char* data = json_dumps(request, JSON_COMPACT | JSON_SORT_KEYS);
    struct json_message_t *msg = alloc_json_message_t(data, strlen(data), t_ctx->connection);
    free(data);
    json_t *result = NULL;

    ValuePointer value_pointer = ValuePointer((const uint8_t*) TEST_VALUE, strlen(TEST_VALUE));
    char* userdata_pointer = strdup("dummy_userdata");
    mock().expectOneCall("test_write_handler")
        .withPointerParameter("connection", t_ctx->connection)
        .withStringParameter("device_id", "test-device")
        .withIntParameter("object_id", 3303)
        .withIntParameter("instance_id", 0)
        .withIntParameter("resource_id", 5700)
        .withIntParameter("operation", OPERATION_READ)
        .withParameterOfType("ValuePointer", "value", (const void*) &value_pointer)
        .withLongIntParameter("value_size", strlen(TEST_VALUE))
        .withPointerParameter("userdata", t_ctx->connection->userdata)
        .andReturnValue(0);

    int rc = pt_receive_write_value(request, params, &result, msg);
    CHECK_EQUAL(0, rc);
    STRNCMP_EQUAL("ok", json_string_value(result), strlen("ok"));

    mock().checkExpectations();

    deallocate_json_message_t(msg);
    free(userdata_pointer);
    free_test_context(t_ctx);
    json_decref(request);
    json_decref(result);
}

TEST(pt_service_api, test_receive_write_value_non_string_value)
{
    const char *userdata = "dummy_userdata";
    struct test_context *t_ctx = connection_initialized(userdata);

    json_t *request = json_object();
    json_object_set_new(request, "jsonrpc", json_string("2.0"));
    json_object_set_new(request, "method", json_string("write"));
    json_object_set_new(request, "id", json_integer(1));

    json_t *params = json_object();
    json_object_set_new(request, "params", params);
    json_object_set_new(params, "value", json_integer(0));
    json_object_set_new(params, "operation", json_integer(OPERATION_READ));

    json_t *uri = json_object();
    json_object_set_new(params, "uri", uri);
    json_object_set_new(uri, "deviceId", json_string("test-device"));
    json_object_set_new(uri, "objectId", json_integer(3303));
    json_object_set_new(uri, "objectInstanceId", json_integer(0));
    json_object_set_new(uri, "resourceId", json_integer(5700));

    char* data = json_dumps(request, JSON_COMPACT | JSON_SORT_KEYS);
    struct json_message_t *msg = alloc_json_message_t(data, strlen(data), t_ctx->connection);
    free(data);
    json_t *result = NULL;

    ValuePointer value_pointer = ValuePointer((const uint8_t*) TEST_VALUE, strlen(TEST_VALUE));
    char* userdata_pointer = strdup("dummy_userdata");

    int rc = pt_receive_write_value(request, params, &result, msg);
    CHECK_EQUAL(1, rc);

    mock().checkExpectations();

    deallocate_json_message_t(msg);
    free(userdata_pointer);
    free_test_context(t_ctx);
    json_decref(request);
    json_decref(result);
}

TEST(pt_service_api, test_receive_write_value_all_fields_ok_failure_on_write)
{
    const char *userdata = "dummy_userdata";
    struct test_context *t_ctx = connection_initialized(userdata);

    json_t *request = json_object();
    json_object_set_new(request, "jsonrpc", json_string("2.0"));
    json_object_set_new(request, "method", json_string("write"));
    json_object_set_new(request, "id", json_integer(1));

    json_t *params = json_object();
    json_object_set_new(request, "params", params);
    json_object_set_new(params, "value", json_string(TEST_VALUE_B64));
    json_object_set_new(params, "operation", json_integer(OPERATION_READ));

    json_t *uri = json_object();
    json_object_set_new(params, "uri", uri);
    json_object_set_new(uri, "deviceId", json_string("test-device"));
    json_object_set_new(uri, "objectId", json_integer(3303));
    json_object_set_new(uri, "objectInstanceId", json_integer(0));
    json_object_set_new(uri, "resourceId", json_integer(5700));

    char* data = json_dumps(request, JSON_COMPACT | JSON_SORT_KEYS);
    struct json_message_t *msg = alloc_json_message_t(data, strlen(data), t_ctx->connection);
    free(data);
    json_t *result = NULL;

    ValuePointer value_pointer = ValuePointer((const uint8_t*) TEST_VALUE, strlen(TEST_VALUE));
    char* userdata_pointer = strdup("dummy_userdata");
    mock().expectOneCall("test_write_handler")
        .withPointerParameter("connection", t_ctx->connection)
        .withStringParameter("device_id", "test-device")
        .withIntParameter("object_id", 3303)
        .withIntParameter("instance_id", 0)
        .withIntParameter("resource_id", 5700)
        .withIntParameter("operation", OPERATION_READ)
        .withParameterOfType("ValuePointer", "value", (const void*) &value_pointer)
        .withLongIntParameter("value_size", strlen(TEST_VALUE))
        .withPointerParameter("userdata", t_ctx->connection->userdata)
        .andReturnValue(1);

    int rc = pt_receive_write_value(request, params, &result, msg);
    CHECK_EQUAL(1, rc);

    json_t *error_code = json_object_get(result, "code");
    CHECK_EQUAL(PT_API_PROTOCOL_TRANSLATOR_CLIENT_WRITE_ERROR, json_integer_value(error_code));

    json_t *error_message = json_object_get(result, "message");
    STRNCMP_EQUAL("Protocol translator client write error.",
                  json_string_value(error_message),
                  strlen("Protocol translator client write error."));

    mock().checkExpectations();

    deallocate_json_message_t(msg);
    free(userdata_pointer);
    free_test_context(t_ctx);
    json_decref(request);
    json_decref(result);
}
