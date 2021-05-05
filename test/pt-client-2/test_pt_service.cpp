#include "CppUTest/TestHarness.h"
#include "CppUTestExt/MockSupport.h"

#include "cpputest-custom-types/value_pointer.h"

#include "pt-client-2/client_send_receive_helper.h"
#include "test-lib/mutex_helper.h"
extern "C" {
#include "jansson.h"
#include <string.h>
#include "pt-client-2/pt_api_internal.h"
#include "pt-client-2/pt_client_helper.h"
#include "common/constants.h"
#include "common/pt_api_error_codes.h"
}
#include "test-lib/msg_api_mocks.h"

struct test_context {
    struct connection *connection;
    pt_client_t *client;
};

#define TEST_VALUE     "test-value"
#define TEST_VALUE_B64 "dGVzdC12YWx1ZQ=="

TEST_GROUP(pt_service_api_2) {
    pt_client_t *client;
    connection_t *connection;

    void setup()
    {
        connection_id_t connection_id = create_client_connection();
        client = active_connection->client;
        client->connection_id = connection_id;
        connection = active_connection;
    }

    void teardown()
    {
        free_client_and_connection(active_connection->id);
        mock().checkExpectations();
        if (mock_msg_api_messages_in_queue() > 0) {
            FAIL("EXTRA MESSAGES IN QUEUE!");
        }
    }
};

pt_status_t test_resource_callback(const connection_id_t connection_id,
                                   const char *device_id,
                                   const uint16_t object_id,
                                   const uint16_t object_instance_id,
                                   const uint16_t resource_id,
                                   uint8_t operation,
                                   const uint8_t *value,
                                   const uint32_t size,
                                   void *userdata)
{
    ValuePointer value_pointer = ValuePointer(value, size);
    return (pt_status_t) mock().actualCall("test_resource_callback")
        .withIntParameter("connection_id", connection_id)
        .withStringParameter("device_id", device_id)
        .withIntParameter("object_id", object_id)
        .withIntParameter("object_instance_id", object_instance_id)
        .withIntParameter("resource_id", resource_id)
        .withIntParameter("operation", operation)
        .withParameterOfType("ValuePointer", "value", &value_pointer)
        .returnIntValue();
}

static void check_error(json_t *result, const int error_code, const char *error_msg)
{
    CHECK(NULL != result);
    json_t *integer_handle = json_object_get(result, "code");
    json_t *message_handle = json_object_get(result, "message");
    CHECK_EQUAL(error_code, json_integer_value(integer_handle));
    STRNCMP_EQUAL(error_msg, json_string_value(message_handle), strlen(error_msg));
}

TEST(pt_service_api_2, test_pt_receive_value_no_request_id)
{
    json_t *request = json_object();
    json_object_set_new(request, "jsonrpc", json_string("2.0"));
    json_object_set_new(request, "method", json_string("write"));
    json_t *params = NULL;
    json_t *result = NULL;

    char* data = json_dumps(request, JSON_COMPACT | JSON_SORT_KEYS);
    struct json_message_t *msg = alloc_json_message_t(data, strlen(data), connection);
    free(data);

    CHECK(1 == pt_receive_write_value(request, params, &result, msg));
    check_error(result, JSONRPC_INVALID_PARAMS, "Invalid params. Missing 'id'-field from request.");

    mock().checkExpectations();
    deallocate_json_message_t(msg);
    json_decref(request);
    json_decref(result);
}

TEST(pt_service_api_2, test_pt_receive_value_check_message_guards)
{
    // Calls should give error as no connection available when they attempt
    // to send the error response to eventloop

    json_t *request = json_object();
    json_object_set_new(request, "jsonrpc", json_string("2.0"));
    json_object_set_new(request, "method", json_string("write"));
    json_object_set_new(request, "id", json_integer(1));

    json_t *params = NULL;
    json_t *result = NULL;

    // Done once to have json message as a string that contains the request id
    char *data = json_dumps(request, JSON_COMPACT | JSON_SORT_KEYS);
    struct json_message_t *msg = alloc_json_message_t(data, strlen(data), connection);
    free(data);

    expect_msg_api_message();
    int rc = pt_receive_write_value(request, params, &result, msg);
    CHECK_EQUAL(JSONRPC_RETURN_CODE_NO_RESPONSE, rc);
    check_error(result, JSONRPC_INVALID_PARAMS, "Invalid params. Missing 'params'-field from request.");
    ValuePointer *value_pointer = expect_outgoing_data_frame("{\"error\":{\"code\":-32602,\"message\":\"Invalid params. Missing 'params'-field from request.\"},\"id\":1,\"jsonrpc\":\"2.0\"}");
    process_event_loop_send_response();
    delete value_pointer;

    /* Add params field */
    params = json_object();
    json_object_set_new(request, "params", params);
    expect_msg_api_message();
    rc = pt_receive_write_value(request, params, &result, msg);
    CHECK_EQUAL(JSONRPC_RETURN_CODE_NO_RESPONSE, rc);
    check_error(result, JSONRPC_INVALID_PARAMS, "Invalid params. Missing 'uri'-field.");
    value_pointer = expect_outgoing_data_frame("{\"error\":{\"code\":-32602,\"message\":\"Invalid params. Missing 'uri'-field.\"},\"id\":1,\"jsonrpc\":\"2.0\"}");
    process_event_loop_send_response();
    delete value_pointer;

    json_t *uri = json_object();
    json_object_set_new(params, "uri", uri);
    expect_msg_api_message();
    rc = pt_receive_write_value(request, params, &result, msg);
    CHECK_EQUAL(JSONRPC_RETURN_CODE_NO_RESPONSE, rc);
    check_error(result, JSONRPC_INVALID_PARAMS, "Invalid params. Missing 'deviceId'-field.");
    value_pointer = expect_outgoing_data_frame("{\"error\":{\"code\":-32602,\"message\":\"Invalid params. Missing 'deviceId'-field.\"},\"id\":1,\"jsonrpc\":\"2.0\"}");
    process_event_loop_send_response();
    delete value_pointer;

    json_object_set_new(uri, "deviceId", json_string("test-device"));
    expect_msg_api_message();
    rc = pt_receive_write_value(request, params, &result, msg);
    CHECK_EQUAL(JSONRPC_RETURN_CODE_NO_RESPONSE, rc);
    check_error(result, JSONRPC_INVALID_PARAMS, "Invalid params. Missing 'objectId'-field.");
    value_pointer = expect_outgoing_data_frame("{\"error\":{\"code\":-32602,\"message\":\"Invalid params. Missing 'objectId'-field.\"},\"id\":1,\"jsonrpc\":\"2.0\"}");
    process_event_loop_send_response();
    delete value_pointer;

    json_object_set_new(uri, "objectId", json_integer(3303));
    expect_msg_api_message();
    rc = pt_receive_write_value(request, params, &result, msg);
    CHECK_EQUAL(JSONRPC_RETURN_CODE_NO_RESPONSE, rc);
    check_error(result, JSONRPC_INVALID_PARAMS, "Invalid params. Missing 'objectInstanceId'-field.");
    value_pointer = expect_outgoing_data_frame("{\"error\":{\"code\":-32602,\"message\":\"Invalid params. Missing 'objectInstanceId'-field.\"},\"id\":1,\"jsonrpc\":\"2.0\"}");
    process_event_loop_send_response();
    delete value_pointer;

    json_object_set_new(uri, "objectInstanceId", json_integer(0));
    expect_msg_api_message();
    rc = pt_receive_write_value(request, params, &result, msg);
    CHECK_EQUAL(JSONRPC_RETURN_CODE_NO_RESPONSE, rc);
    check_error(result, JSONRPC_INVALID_PARAMS, "Invalid params. Missing 'resourceId'-field.");
    value_pointer = expect_outgoing_data_frame("{\"error\":{\"code\":-32602,\"message\":\"Invalid params. Missing 'resourceId'-field.\"},\"id\":1,\"jsonrpc\":\"2.0\"}");
    process_event_loop_send_response();
    delete value_pointer;

    json_object_set_new(uri, "resourceId", json_integer(5700));
    expect_msg_api_message();
    rc = pt_receive_write_value(request, params, &result, msg);
    CHECK_EQUAL(JSONRPC_RETURN_CODE_NO_RESPONSE, rc);
    check_error(result, JSONRPC_INVALID_PARAMS, "Invalid params. Missing 'value'-field.");
    value_pointer = expect_outgoing_data_frame("{\"error\":{\"code\":-32602,\"message\":\"Invalid params. Missing 'value'-field.\"},\"id\":1,\"jsonrpc\":\"2.0\"}");
    process_event_loop_send_response();
    delete value_pointer;

    json_object_set_new(params, "value", json_string(TEST_VALUE_B64));
    expect_msg_api_message();
    rc = pt_receive_write_value(request, params, &result, msg);
    CHECK_EQUAL(JSONRPC_RETURN_CODE_NO_RESPONSE, rc);
    check_error(result, JSONRPC_INVALID_PARAMS, "Invalid params. Missing 'operation'-field.");
    value_pointer = expect_outgoing_data_frame("{\"error\":{\"code\":-32602,\"message\":\"Invalid params. Missing 'operation'-field.\"},\"id\":1,\"jsonrpc\":\"2.0\"}");
    process_event_loop_send_response();
    delete value_pointer;

    mock().checkExpectations();
    deallocate_json_message_t(msg);
    json_decref(request);
}

TEST(pt_service_api_2, test_receive_write_value_all_fields_ok_success_on_write_execute_no_data)
{
    const char *userdata = "dummy_userdata";
    const char *empty_string = "";

    client->userdata = (void *) userdata;

    pt_status_t status;
    mh_expect_mutexing(&api_mutex);
    status = pt_device_create(client->connection_id, "test-device", 3600, NONE);
    CHECK(PT_STATUS_SUCCESS == status);
    mh_expect_mutexing(&api_mutex);
    status = pt_device_add_resource_with_callback(client->connection_id,
                                                  "test-device",
                                                  3303,
                                                  0,
                                                  5700,
                                                  /* resource name */ NULL,
                                                  LWM2M_STRING,
                                                  OPERATION_EXECUTE,
                                                  NULL,
                                                  0,
                                                  free,
                                                  test_resource_callback);
    CHECK(PT_STATUS_SUCCESS == status);

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
    struct json_message_t *msg = alloc_json_message_t(data, strlen(data), connection);
    free(data);
    json_t *result = NULL;

    ValuePointer value_pointer = ValuePointer(NULL, 0);
    mock().expectOneCall("test_resource_callback")
            .withIntParameter("connection_id", client->connection_id)
            .withStringParameter("device_id", "test-device")
            .withIntParameter("object_id", 3303)
            .withIntParameter("object_instance_id", 0)
            .withIntParameter("resource_id", 5700)
            .withIntParameter("operation", OPERATION_EXECUTE)
            .withParameterOfType("ValuePointer", "value", &value_pointer);

    expect_msg_api_message();

    int rc = pt_receive_write_value(request, params, &result, msg);
    CHECK_EQUAL(JSONRPC_RETURN_CODE_NO_RESPONSE, rc);
    POINTERS_EQUAL(result, NULL);

    ValuePointer *value_pointer2 = expect_outgoing_data_frame("{\"id\":1,\"jsonrpc\":\"2.0\",\"result\":\"ok\"}");
    process_event_loop_send_response();
    delete value_pointer2;

    mock().checkExpectations();

    deallocate_json_message_t(msg);
    json_decref(request);
}

TEST(pt_service_api_2, test_receive_write_value_all_fields_ok_success_on_write)
{
    const char *userdata = "dummy_userdata";
    client->userdata = (void *) userdata;

    pt_status_t status;
    mh_expect_mutexing(&api_mutex);
    status = pt_device_create(client->connection_id, "test-device", 3600, NONE);
    CHECK(PT_STATUS_SUCCESS == status);
    mh_expect_mutexing(&api_mutex);
    status = pt_device_add_resource_with_callback(client->connection_id,
                                                  "test-device",
                                                  3303,
                                                  0,
                                                  5700,
                                                  /* resource name */ NULL,
                                                  LWM2M_STRING,
                                                  OPERATION_WRITE,
                                                  (uint8_t *) strdup("initial-value"),
                                                  strlen("initial-value"),
                                                  free,
                                                  test_resource_callback);
    CHECK(PT_STATUS_SUCCESS == status);

    json_t *request = json_object();
    json_object_set_new(request, "jsonrpc", json_string("2.0"));
    json_object_set_new(request, "method", json_string("write"));
    json_object_set_new(request, "id", json_integer(1));

    json_t *params = json_object();
    json_object_set_new(request, "params", params);
    json_object_set_new(params, "value", json_string(TEST_VALUE_B64));
    json_object_set_new(params, "operation", json_integer(OPERATION_WRITE));

    json_t *uri = json_object();
    json_object_set_new(params, "uri", uri);
    json_object_set_new(uri, "deviceId", json_string("test-device"));
    json_object_set_new(uri, "objectId", json_integer(3303));
    json_object_set_new(uri, "objectInstanceId", json_integer(0));
    json_object_set_new(uri, "resourceId", json_integer(5700));

    char *data = json_dumps(request, JSON_COMPACT | JSON_SORT_KEYS);
    struct json_message_t *msg = alloc_json_message_t(data, strlen(data), connection);
    free(data);
    json_t *result = NULL;

    ValuePointer value_pointer = ValuePointer((uint8_t*) TEST_VALUE, strlen(TEST_VALUE));
    mock().expectOneCall("test_resource_callback")
            .withIntParameter("connection_id", client->connection_id)
            .withStringParameter("device_id", "test-device")
            .withIntParameter("object_id", 3303)
            .withIntParameter("object_instance_id", 0)
            .withIntParameter("resource_id", 5700)
            .withIntParameter("operation", OPERATION_WRITE)
            .withParameterOfType("ValuePointer", "value", &value_pointer);

    expect_msg_api_message();

    int rc = pt_receive_write_value(request, params, &result, msg);
    CHECK_EQUAL(JSONRPC_RETURN_CODE_NO_RESPONSE, rc);
    POINTERS_EQUAL(result, NULL);

    ValuePointer *value_pointer2 = expect_outgoing_data_frame("{\"id\":1,\"jsonrpc\":\"2.0\",\"result\":\"ok\"}");
    process_event_loop_send_response();
    delete value_pointer2;

    mock().checkExpectations();

    deallocate_json_message_t(msg);
    json_decref(request);
}

TEST(pt_service_api_2, test_receive_write_value_non_string_value)
{
    const char *userdata = "dummy_userdata";
    client->userdata = (void *) userdata;

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
    struct json_message_t *msg = alloc_json_message_t(data, strlen(data), connection);
    free(data);
    json_t *result = NULL;

    ValuePointer value_pointer = ValuePointer((const uint8_t*) TEST_VALUE, strlen(TEST_VALUE));
    char* userdata_pointer = strdup("dummy_userdata");

    expect_msg_api_message();
    int rc = pt_receive_write_value(request, params, &result, msg);
    CHECK_EQUAL(JSONRPC_RETURN_CODE_NO_RESPONSE, rc);

    ValuePointer *value_pointer2 = expect_outgoing_data_frame("{\"error\":{\"code\":-32602,\"message\":\"Invalid params.\"},\"id\":1,\"jsonrpc\":\"2.0\"}");
    process_event_loop_send_response();

    mock().checkExpectations();

    deallocate_json_message_t(msg);
    free(userdata_pointer);
    json_decref(request);
    delete value_pointer2;
}

TEST(pt_service_api_2, test_receive_write_value_all_fields_ok_failure_on_write)
{
    const char *userdata = "dummy_userdata";
    client->userdata = (void *) userdata;

    json_t *request = json_object();
    json_object_set_new(request, "jsonrpc", json_string("2.0"));
    json_object_set_new(request, "method", json_string("write"));
    json_object_set_new(request, "id", json_integer(1));

    json_t *params = json_object();
    json_object_set_new(request, "params", params);
    json_object_set_new(params, "value", json_string(TEST_VALUE_B64));
    json_object_set_new(params, "operation", json_integer(OPERATION_WRITE));

    json_t *uri = json_object();
    json_object_set_new(params, "uri", uri);
    json_object_set_new(uri, "deviceId", json_string("test-device"));
    json_object_set_new(uri, "objectId", json_integer(3303));
    json_object_set_new(uri, "objectInstanceId", json_integer(0));
    json_object_set_new(uri, "resourceId", json_integer(5700));

    char *data = json_dumps(request, JSON_COMPACT | JSON_SORT_KEYS);
    struct json_message_t *msg = alloc_json_message_t(data, strlen(data), connection);
    free(data);
    json_t *result = NULL;

    expect_msg_api_message();
    int rc = pt_receive_write_value(request, params, &result, msg);
    CHECK_EQUAL(JSONRPC_RETURN_CODE_NO_RESPONSE, rc);

    json_t *error_code = json_object_get(result, "code");
    CHECK_EQUAL(PT_API_PROTOCOL_TRANSLATOR_CLIENT_WRITE_ERROR, json_integer_value(error_code));

    json_t *error_message = json_object_get(result, "message");
    STRNCMP_EQUAL("Protocol translator client write error.",
                  json_string_value(error_message),
                  strlen("Protocol translator client write error."));

    ValuePointer *value_pointer = expect_outgoing_data_frame("{\"error\":{\"code\":-30100,\"data\":\"Error in client write.\",\"message\":\"Protocol translator client write error.\"},\"id\":1,\"jsonrpc\":\"2.0\"}");

    process_event_loop_send_response();

    mock().checkExpectations();

    deallocate_json_message_t(msg);
    json_decref(request);
    delete value_pointer;
}

TEST(pt_service_api_2, test_devices_call_resource_callback_check_parameter_guards)
{
    // connection not found
    CHECK(PT_STATUS_INVALID_PARAMETERS == pt_devices_call_resource_callback(-1, NULL, 0, 0, 0, 0, 0, 0));
    // connection found with id 1
    CHECK(PT_STATUS_INVALID_PARAMETERS ==
          pt_devices_call_resource_callback(client->connection_id, NULL, 0, 0, 0, 0, 0, 0));

    // connection found with id 1, devices in client NULL
    free(client->devices->list);
    free(client->devices);
    client->devices = NULL;
    CHECK(PT_STATUS_INVALID_PARAMETERS == pt_devices_call_resource_callback(1, NULL, 0, 0, 0, 0, 0, 0));

    mock().checkExpectations();
}

TEST(pt_service_api_2, test_devices_call_resource_callback_device)
{
    pt_status_t status;
    mh_expect_mutexing(&api_mutex);
    status =pt_device_create(client->connection_id, "match", 3600, NONE);
    CHECK_EQUAL(PT_STATUS_SUCCESS, status);

    /* Add object, instance and resource to have more than one element in list */
    mh_expect_mutexing(&api_mutex);
    pt_device_create(client->connection_id, "extra", 3600, NONE);
    CHECK(PT_STATUS_SUCCESS == status);
    mh_expect_mutexing(&api_mutex);
    status = pt_device_add_resource(client->connection_id,
                                    "extra",
                                    1,
                                    1,
                                    1,
                                    /* resource name */ NULL,
                                    LWM2M_STRING,
                                    (uint8_t *) strdup("extra-value"),
                                    strlen("extra-value"),
                                    free);
    CHECK(PT_STATUS_SUCCESS == status);

    const char *device_id = "match";
    CHECK(PT_STATUS_NOT_FOUND == pt_devices_call_resource_callback(client->connection_id, device_id, 0, 0, 0, 0, 0, 0));

    /* Add resource with ID 1 and static value and no free callback */
    mh_expect_mutexing(&api_mutex);
    status = pt_device_add_resource(client->connection_id,
                                    "match",
                                    1,
                                    1,
                                    1,
                                    /* resource name */ NULL,
                                    LWM2M_STRING,
                                    (uint8_t *) "test-value",
                                    strlen("test-value"),
                                    NULL);
    CHECK(PT_STATUS_SUCCESS == status);

    /* Add resource with ID 2 */
    uint16_t *int_value = (uint16_t *) malloc(sizeof(uint16_t));
    *int_value = 0;
    mh_expect_mutexing(&api_mutex);
    status = pt_device_add_resource_with_callback(client->connection_id,
                                                  "match",
                                                  1,
                                                  1,
                                                  2,
                                                  /* resource name */ NULL,
                                                  LWM2M_INTEGER,
                                                  OPERATION_READ | OPERATION_WRITE,
                                                  (uint8_t *) int_value,
                                                  sizeof(uint16_t),
                                                  free,
                                                  test_resource_callback);
    CHECK(PT_STATUS_SUCCESS == status);

    /* Add resource with ID 3 */
    float *float_value = (float *) malloc(sizeof(float));
    *float_value = 0.0;
    mh_expect_mutexing(&api_mutex);
    status = pt_device_add_resource_with_callback(client->connection_id,
                                                  "match",
                                                  1,
                                                  1,
                                                  3,
                                                  /* resource name */ NULL,
                                                  LWM2M_FLOAT,
                                                  OPERATION_EXECUTE,
                                                  (uint8_t *) float_value,
                                                  sizeof(float),
                                                  free,
                                                  test_resource_callback);
    CHECK(PT_STATUS_SUCCESS == status);

    /* Resource is found, operation not supported -> error */
    uint16_t *new_int_value = (uint16_t *) malloc(sizeof(uint16_t));
    *new_int_value = 100;
    CHECK(PT_STATUS_ERROR == pt_devices_call_resource_callback(client->connection_id,
                                                               device_id,
                                                               /* object id */ 1,
                                                               /* instance id */ 1,
                                                               /* resource id */ 1,
                                                               OPERATION_WRITE,
                                                               (uint8_t *) new_int_value,
                                                               sizeof(uint16_t)));

    /* Resource is found, operation supported (write) -> callback called. */
    ValuePointer value_pointer = ValuePointer((uint8_t *) new_int_value, sizeof(uint16_t));
    mock().expectOneCall("test_resource_callback")
            .withIntParameter("connection_id", client->connection_id)
            .withStringParameter("device_id", "match")
            .withIntParameter("object_id", 1)
            .withIntParameter("object_instance_id", 1)
            .withIntParameter("resource_id", 2)
            .withIntParameter("operation", OPERATION_WRITE)
            .withParameterOfType("ValuePointer", "value", &value_pointer);
    CHECK(PT_STATUS_SUCCESS == pt_devices_call_resource_callback(client->connection_id,
                                                                 device_id,
                                                                 /* object id */ 1,
                                                                 /* instance id */ 1,
                                                                 /* resource id */ 2,
                                                                 OPERATION_WRITE,
                                                                 (uint8_t *) new_int_value,
                                                                 sizeof(uint16_t)));

    /* Resource is found, operation supported (execute) -> callback called. */
    ValuePointer value_pointer_execute = ValuePointer(NULL, 0);
    mock().expectOneCall("test_resource_callback")
            .withIntParameter("connection_id", client->connection_id)
            .withStringParameter("device_id", "match")
            .withIntParameter("object_id", 1)
            .withIntParameter("object_instance_id", 1)
            .withIntParameter("resource_id", 3)
            .withIntParameter("operation", OPERATION_EXECUTE)
            .withParameterOfType("ValuePointer", "value", &value_pointer_execute);
    CHECK(PT_STATUS_SUCCESS == pt_devices_call_resource_callback(client->connection_id,
                                                                 device_id,
                                                                 /* object id */ 1,
                                                                 /* instance id */ 1,
                                                                 /* resource id */ 3,
                                                                 OPERATION_EXECUTE,
                                                                 NULL,
                                                                 0));

    /* Test device with no match */
    CHECK(PT_STATUS_NOT_FOUND ==
          pt_devices_call_resource_callback(client->connection_id, "no-match", 0, 0, 0, 0, 0, 0));

    mock().checkExpectations();
    free(new_int_value);
}

TEST(pt_service_api_2, test_receive_certificate_renewal_result_successfully)
{
    const char *userdata = "dummy_userdata";
    client->userdata = (void *) userdata;

    json_t *request = json_object();
    json_object_set_new(request, "jsonrpc", json_string("2.0"));
    json_object_set_new(request, "method", json_string("write"));
    json_object_set_new(request, "id", json_integer(1));

    json_t *params = json_object();
    json_object_set_new(request, "params", params);
    json_object_set_new(params, "certificate", json_string("pt_cert_name"));
    json_object_set_new(params, "status", json_integer(0));
    json_object_set_new(params, "description", json_string("CE_STATUS_SUCCESS"));
    json_object_set_new(params, "initiator", json_integer(0));
    char *data = json_dumps(request, JSON_COMPACT | JSON_SORT_KEYS);
    struct json_message_t *msg = alloc_json_message_t(data, strlen(data), connection);
    free(data);
    json_t *result = NULL;
    mock().expectOneCall("test_certificate_renewal_notifier_cb")
            .withStringParameter("name", "pt_cert_name")
            .withIntParameter("status", 0)
            .withIntParameter("initiator", 0)
            .withPointerParameter("userdata", (void *) userdata)
            .withStringParameter("description", "CE_STATUS_SUCCESS");
    int rc = pt_receive_certificate_renewal_result(request, params, &result, msg);
    CHECK_EQUAL(0, rc);
    STRCMP_EQUAL("ok", json_string_value(result));
    mock().checkExpectations();
    deallocate_json_message_t(msg);
    json_decref(request);
    json_decref(result);
}

