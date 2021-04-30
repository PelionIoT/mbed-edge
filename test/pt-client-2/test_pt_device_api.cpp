#ifndef _GNU_SOURCE
#define _GNU_SOURCE // needed for strdup
#endif
#include "CppUTest/TestHarness.h"
#include "CppUTestExt/MockSupport.h"
#include <string.h>
#include <stdio.h>

extern "C" {
#include "pt-client-2/ipso_enums.h"
#include "pt-client-2/pt_api.h"
#include "pt-client-2/pt_api_internal.h"
#include "pt-client-2/pt_certificate_api_internal.h"
}
#include "pt-client-2/client_send_receive_helper.h"
#include "test-lib/msg_api_mocks.h"
#include "cpputest-custom-types/value_pointer.h"
#define TRACE_GROUP "PtDevAPI"
#include "mbed-trace/mbed_trace.h"
#include "test-lib/mutex_helper.h"
#include <stdlib.h>


typedef struct {
    pt_client_t *client;
    ValuePointer *register_value_pointer1;
    ValuePointer *register_value_pointer2;
    ValuePointer *unregister_value_pointer1;
    ValuePointer *unregister_value_pointer2;
} devices_test_data_t;

static void free_devices_data(devices_test_data_t *devices_data)
{
    delete devices_data->register_value_pointer1;
    delete devices_data->register_value_pointer2;
    delete devices_data->unregister_value_pointer1;
    delete devices_data->unregister_value_pointer2;
    free(devices_data);
}

TEST_GROUP(pt_device_2)
{
    void setup()
    {
        reset_rpc_id_counter();
        rpc_set_generate_msg_id(test_msg_generate_id);
        mock_msg_api_wipeout_messages();
    }

    void teardown()
    {
        // These tests should pop the message API message queue and do some check on the message content.
        CHECK_EQUAL(0, mock_msg_api_messages_in_queue());
    }
};

TEST_GROUP(pt_device_2_with_connection)
{
    void setup()
    {
        reset_rpc_id_counter();
        rpc_set_generate_msg_id(test_msg_generate_id);

        mock_msg_api_wipeout_messages();
        active_connection_id = create_client_connection();
    }

    void teardown()
    {
        // These tests should pop the message API message queue and do some check on the message content.
        CHECK_EQUAL(0, mock_msg_api_messages_in_queue());
        free_client_and_connection(active_connection_id);
        active_connection_id = PT_API_CONNECTION_ID_INVALID;
    }
};

TEST(pt_device_2_with_connection, test_pt_device_create_with_no_userdata)
{
    mh_expect_mutexing(&api_mutex);
    pt_status_t status = pt_device_create(active_connection_id, "test-device", 3600, NONE);
    CHECK(PT_STATUS_SUCCESS == status);
    mock().checkExpectations();
}

TEST(pt_device_2_with_connection, test_userdata_api)
{
    pt_status_t status;
    char *device_attributes = NULL;
    char *device_attributes2 = NULL;
    const char *device_name = "resourceful-device";
    asprintf(&device_attributes, "device_type=immovable");
    asprintf(&device_attributes2, "device userdata changed");
    pt_userdata_t *changed_userdata = pt_api_create_userdata(device_attributes2, (pt_userdata_free_cb_t) free);
    mh_expect_mutexing(&api_mutex);
    pt_userdata_t *device_userdata = pt_api_create_userdata(device_attributes, (pt_userdata_free_cb_t) free);
    CHECK(device_userdata != NULL);
    status = pt_device_create_with_userdata(active_connection_id, device_name, 3600, NONE, device_userdata);
    CHECK_EQUAL(PT_STATUS_SUCCESS, status);
    mh_expect_mutexing(&api_mutex);
    pt_userdata_t *userdata = pt_device_get_userdata(active_connection_id, device_name);
    STRCMP_EQUAL("device_type=immovable", (const char *) (userdata->data));
    mh_expect_mutexing(&api_mutex);
    status = pt_device_set_userdata(active_connection_id, device_name, changed_userdata);
    CHECK_EQUAL(PT_STATUS_SUCCESS, status);
    mh_expect_mutexing(&api_mutex);
    userdata = pt_device_get_userdata(active_connection_id, device_name);
    STRCMP_EQUAL("device userdata changed", (const char *) (userdata->data));
    mh_expect_mutexing(&api_mutex);
    status = pt_device_add_resource(active_connection_id,
                                    device_name,
                                    TEMPERATURE_SENSOR,
                                    1,
                                    MIN_MEASURED_VALUE,
                                    /* resource name */ NULL,
                                    LWM2M_OPAQUE,
                                    NULL,
                                    0,
                                    free);
    CHECK_EQUAL(PT_STATUS_SUCCESS, status);
    char *resource_attributes = NULL;
    asprintf(&resource_attributes, "minimum measured value related data.");
    mh_expect_mutexing(&api_mutex);
    pt_userdata_t *resource_userdata = pt_api_create_userdata(resource_attributes, (pt_userdata_free_cb_t) free);
    status = pt_resource_set_userdata(active_connection_id,
                                      device_name,
                                      TEMPERATURE_SENSOR,
                                      1,
                                      MIN_MEASURED_VALUE,
                                      resource_userdata);
    CHECK_EQUAL(PT_STATUS_SUCCESS, status);

    mh_expect_mutexing(&api_mutex);
    pt_userdata_t *userdata2 = pt_resource_get_userdata(active_connection_id,
                                                        device_name,
                                                        TEMPERATURE_SENSOR,
                                                        1,
                                                        MIN_MEASURED_VALUE);
    STRCMP_EQUAL("minimum measured value related data.", (const char *) (userdata2->data));
    mock().checkExpectations();
}

TEST(pt_device_2_with_connection, test_device_and_resource_exists)
{
    const char *device_name = "resourceful-device";

    pt_status_t status;
    mh_expect_mutexing(&api_mutex);
    pt_device_create(active_connection_id, device_name, 3600, NONE);
    mh_expect_mutexing(&api_mutex);
    status = pt_device_add_resource(active_connection_id,
                                    device_name,
                                    TEMPERATURE_SENSOR,
                                    1,
                                    MIN_MEASURED_VALUE,
                                    /* resource name */ NULL,
                                    LWM2M_OPAQUE,
                                    NULL,
                                    0,
                                    free);
    CHECK_EQUAL(PT_STATUS_SUCCESS, status);
    mh_expect_mutexing(&api_mutex);
    bool exists_flag = pt_device_exists(active_connection_id, device_name);
    CHECK_EQUAL(true, exists_flag);

    mh_expect_mutexing(&api_mutex);
    exists_flag = pt_device_exists(active_connection_id, "no-such-device-name");
    CHECK_EQUAL(false, exists_flag);

    mh_expect_mutexing(&api_mutex);
    exists_flag = pt_device_resource_exists(active_connection_id,
                                            device_name,
                                            TEMPERATURE_SENSOR,
                                            1,
                                            MIN_MEASURED_VALUE);
    CHECK_EQUAL(true, exists_flag);

    mh_expect_mutexing(&api_mutex);
    exists_flag = pt_device_resource_exists(active_connection_id,
                                            device_name,
                                            TEMPERATURE_SENSOR,
                                            1,
                                            MAX_MEASURED_VALUE);
    CHECK_EQUAL(false, exists_flag);

    mh_expect_mutexing(&api_mutex);
    exists_flag = pt_device_resource_exists(active_connection_id,
                                            "no-this-device-either",
                                            TEMPERATURE_SENSOR,
                                            1,
                                            MAX_MEASURED_VALUE);
    CHECK_EQUAL(false, exists_flag);
    mock().checkExpectations();
}

static void create_test_device(const char *name)
{
    pt_status_t status;
    char *device_attributes = NULL;
    asprintf(&device_attributes, "device_type=immovable");
    pt_userdata_t *device_data = pt_api_create_userdata(device_attributes, (pt_userdata_free_cb_t) free);
    mh_expect_mutexing(&api_mutex);
    status = pt_device_create_with_userdata(active_connection_id, name, 3600, NONE, device_data);
    CHECK_EQUAL(PT_STATUS_SUCCESS, status);

    mh_expect_mutexing(&api_mutex);
    status = pt_device_add_resource(active_connection_id,
                                    name,
                                    TEMPERATURE_SENSOR,
                                    1,
                                    MIN_MEASURED_VALUE,
                                    /* resource name */ NULL,
                                    LWM2M_OPAQUE,
                                    NULL,
                                    0,
                                    free);
    CHECK(PT_STATUS_SUCCESS == status);
    mock().checkExpectations();
}

TEST(pt_device_2_with_connection, test_pt_device_create_with_userdata_and_resource)
{
    create_test_device("test-device");
    mock().checkExpectations();
}

static void test_device_registation_success_handler(connection_id_t connection_id,
                                                    const char *device_id,
                                                    void *userdata)
{
    mock().actualCall("test_device_registation_success_handler");
}

static void test_device_registation_failure_handler(connection_id_t connection_id,
                                                    const char *device_id,
                                                    void *userdata)
{
    mock().actualCall("test_device_registation_failure_handler");
}

static void test_device_unregistation_success_handler(connection_id_t connection_id,
                                                      const char *device_id,
                                                      void *userdata)
{
    mock().actualCall("test_device_unregistation_success_handler");
}

static void test_device_unregistation_failure_handler(connection_id_t connection_id,
                                                      const char *device_id,
                                                      void *userdata)
{
    mock().actualCall("test_device_unregistation_failure_handler");
}

TEST(pt_device_2_with_connection, test_pt_device_register_no_connection)
{
    const char *device_name = "test-device";
    void *my_userdata = (void *) 123;
    create_test_device(device_name);
    pt_client_t *client = destroy_active_connection();
    mock().checkExpectations();
    mh_expect_mutexing(&api_mutex); // due to pt_api_send_to_message_loop
    pt_status_t status = pt_device_register(PT_API_CONNECTION_ID_INVALID,
                                            device_name,
                                            test_device_registation_success_handler,
                                            test_device_registation_failure_handler,
                                            my_userdata);
    CHECK_EQUAL(PT_STATUS_INVALID_PARAMETERS, status);
    destroy_client(client);
    mock().checkExpectations();
}

static void register_device(pt_client_t *client)
{
    const char *device_name = "test-device";
    create_test_device(device_name);
    void *my_userdata = (void *) 123;
    mh_expect_mutexing(&api_mutex); // due to pt_api_send_to_message_loop
    expect_msg_api_message();
    pt_device_register(active_connection_id,
                       device_name,
                       test_device_registation_success_handler,
                       test_device_registation_failure_handler,
                       my_userdata);

    ValuePointer *value_pointer = expect_outgoing_data_frame(
            "{\"id\":\"1\",\"jsonrpc\":\"2.0\",\"method\":\"device_register\",\"params\":{"
            "\"deviceId\":\"test-device\",\"lifetime\":3600,\"objects\":[{\"objectId\":3303,"
            "\"objectInstances\":[{\"objectInstanceId\":1,\"resources\":[{\"operations\":1,"
            "\"resourceId\":5601,\"type\":\"opaque\",\"value\":\"\"}]}]}],\"queuemode\":\"-\"}}");
    process_event_loop_send_message(true /* connection found */);
    mock().checkExpectations();
    receive_incoming_data_frame_expectations();
    find_client_device_expectations();
    mock().expectOneCall("test_device_registation_success_handler");
    receive_incoming_data_frame(active_connection, "{\"id\":\"1\",\"jsonrpc\":\"2.0\",\"result\":\"ok\"}");
    delete value_pointer;
}

static void pt_register_success_cb(void *userdata)
{
    (void) userdata;
    mock().actualCall("pt_register_success_cb");
}

static void pt_register_failure_cb(void *userdata)
{
    (void) userdata;
    mock().actualCall("pt_register_failure_cb");
}

TEST(pt_device_2_with_connection, test_pt_register_protocol_translator_success)
{
    pt_status_t status;
    void *userdata = (void *) 456;
    expect_msg_api_message();
    CHECK_EQUAL(false, active_connection->client->registered);
    ValuePointer *value_pointer = expect_outgoing_data_frame(
            "{\"id\":\"1\",\"jsonrpc\":\"2.0\",\"method\":\"protocol_"
            "translator_register\",\"params\":{\"name\":\"test_protocol_translator\"}}");
    status = pt_register_protocol_translator(active_connection_id,
                                             pt_register_success_cb,
                                             pt_register_failure_cb,
                                             "test_protocol_translator",
                                             userdata);
    CHECK(PT_STATUS_SUCCESS == status);
    process_event_loop_send_message(true /* connection found */);
    receive_incoming_data_frame_expectations();
    mh_expect_mutexing(&api_mutex);
    mock().expectOneCall("pt_register_success_cb");
    receive_incoming_data_frame(active_connection, "{\"id\":\"1\",\"jsonrpc\":\"2.0\",\"result\":\"ok\"}");
    CHECK_EQUAL(true, active_connection->client->registered);
    mock().checkExpectations();
    delete value_pointer;
}

TEST(pt_device_2_with_connection, test_pt_register_protocol_translator_no_name)
{
    pt_status_t status;
    void *userdata = (void *) 456;
    CHECK_EQUAL(false, active_connection->client->registered);
    status = pt_register_protocol_translator(active_connection_id,
                                             pt_register_success_cb,
                                             pt_register_failure_cb,
                                             "",
                                             userdata);
    CHECK(PT_STATUS_INVALID_PARAMETERS == status);
    CHECK_EQUAL(false, active_connection->client->registered);
    mock().checkExpectations();
}

TEST(pt_device_2_with_connection, test_pt_register_protocol_translator_customer_cb_fails)
{
    pt_status_t status;
    void *userdata = (void *) 456;
    CHECK_EQUAL(false, active_connection->client->registered);
    status = pt_register_protocol_translator(active_connection_id,
                                             NULL,
                                             pt_register_failure_cb,
                                             "test",
                                             userdata);
    CHECK(PT_STATUS_ALLOCATION_FAIL == status);
    CHECK_EQUAL(false, active_connection->client->registered);
    mock().checkExpectations();
}

TEST(pt_device_2_with_connection, test_pt_register_protocol_translator_msg_api_msg_fails)
{
    pt_status_t status;
    void *userdata = (void *) 456;
    expect_msg_api_message_sending_fails();
    CHECK_EQUAL(false, active_connection->client->registered);
    status = pt_register_protocol_translator(active_connection_id,
                                             pt_register_success_cb,
                                             pt_register_failure_cb,
                                             "test_protocol_translator",
                                             userdata);
    CHECK(PT_STATUS_ERROR == status);
    CHECK_EQUAL(false, active_connection->client->registered);
    mock().checkExpectations();
}

TEST(pt_device_2_with_connection, test_pt_register_protocol_translator_connection_disappears)
{
    pt_status_t status;
    void *userdata = (void *) 456;
    expect_msg_api_message();
    pt_client_t *client = active_connection->client;
    CHECK_EQUAL(false, client->registered);
    status = pt_register_protocol_translator(active_connection_id,
                                             pt_register_success_cb,
                                             pt_register_failure_cb,
                                             "test_protocol_translator",
                                             userdata);
    CHECK(PT_STATUS_SUCCESS == status);
    client = destroy_active_connection();
    mock().expectOneCall("pt_register_failure_cb");
    process_event_loop_send_message(false /* connection found */);
    CHECK_EQUAL(false, client->registered);
    destroy_client(client);
    mock().checkExpectations();
}

TEST(pt_device_2_with_connection, test_pt_register_protocol_translator_failure)
{
    pt_status_t status;
    void *userdata = (void *) 457;
    expect_msg_api_message();
    CHECK_EQUAL(false, active_connection->client->registered);
    ValuePointer *value_pointer = expect_outgoing_data_frame(
            "{\"id\":\"1\",\"jsonrpc\":\"2.0\",\"method\":\"protocol_"
            "translator_register\",\"params\":{\"name\":\"test_protocol_translator\"}}");
    status = pt_register_protocol_translator(active_connection_id,
                                             pt_register_success_cb,
                                             pt_register_failure_cb,
                                             "test_protocol_translator",
                                             userdata);
    CHECK(PT_STATUS_SUCCESS == status);
    process_event_loop_send_message(true /* connection found */);
    receive_incoming_data_frame_expectations();
    mh_expect_mutexing(&api_mutex);
    mock().expectOneCall("pt_register_failure_cb");
    receive_incoming_data_frame(active_connection,
                                "{\"id\":\"1\",\"jsonrpc\":\"2.0\",\"error\":{\"code\":-30002,\"message\":\"Protocol "
                                "translator already registered.\"}}");
    CHECK_EQUAL(false, active_connection->client->registered);
    mock().checkExpectations();
    delete value_pointer;
}

TEST(pt_device_2, test_pt_device_register_connection_id_invalid)
{
    const char *device_name = "test-device";
    void *my_userdata = (void *) 123;
    mh_expect_mutexing(&api_mutex);
    pt_status_t status = pt_device_register(active_connection_id,
                                            device_name,
                                            test_device_registation_success_handler,
                                            test_device_registation_failure_handler,
                                            my_userdata);
    CHECK_EQUAL(PT_STATUS_INVALID_PARAMETERS, status);
    mock().checkExpectations();
}

TEST(pt_device_2_with_connection, test_pt_device_register_device_null)
{
    void *my_userdata = (void *) 123;
    mh_expect_mutexing(&api_mutex);
    pt_status_t status = pt_device_register(active_connection_id,
                                            NULL,
                                            test_device_registation_success_handler,
                                            test_device_registation_failure_handler,
                                            my_userdata);
    CHECK_EQUAL(PT_STATUS_ERROR, status);
    mock().checkExpectations();
}

TEST(pt_device_2_with_connection, test_pt_device_register_success)
{
    register_device(active_connection->client);
    mock().checkExpectations();
}

TEST(pt_device_2_with_connection, test_pt_device_register_fails_already_registered)
{
    const char *device_name = "test-device";
    void *my_userdata = (void *) 321;
    create_test_device(device_name);
    mh_expect_mutexing(&api_mutex);
    expect_msg_api_message();
    pt_device_register(active_connection_id,
                       device_name,
                       test_device_registation_success_handler,
                       test_device_registation_failure_handler,
                       my_userdata);

    ValuePointer *value_pointer = expect_outgoing_data_frame(
            "{\"id\":\"1\",\"jsonrpc\":\"2.0\",\"method\":\"device_register\",\"params\":{"
            "\"deviceId\":\"test-device\",\"lifetime\":3600,\"objects\":[{\"objectId\":3303,"
            "\"objectInstances\":[{\"objectInstanceId\":1,\"resources\":[{\"operations\":1,"
            "\"resourceId\":5601,\"type\":\"opaque\",\"value\":\"\"}]}]}],\"queuemode\":\"-\"}}");
    process_event_loop_send_message(true /* connection found */);
    receive_incoming_data_frame_expectations();
    find_client_device_expectations();
    mock().expectOneCall("test_device_registation_failure_handler");
    receive_incoming_data_frame(active_connection,
                                "{\"id\":\"1\",\"jsonrpc\":\"2.0\",\"error\":{\"code\":-30005,\"message\":\"Cannot "
                                "register endpoint, because it's "
                                "already registered.\"}}");
    mock().checkExpectations();
    delete value_pointer;
}

TEST(pt_device_2_with_connection, test_pt_unregister_device_success)
{
    register_device(active_connection->client);
    void *my_userdata = (void *) 124;
    mh_expect_mutexing(&api_mutex);
    expect_msg_api_message();
    pt_device_unregister(active_connection_id,
                         "test-device",
                         test_device_unregistation_success_handler,
                         test_device_unregistation_failure_handler,
                         my_userdata);
    ValuePointer *value_pointer = expect_outgoing_data_frame(
            "{\"id\":\"2\",\"jsonrpc\":\"2.0\",\"method\":\"device_unregister\","
            "\"params\":{\"deviceId\":\"test-device\"}}");
    process_event_loop_send_message(true /* connection found */);
    receive_incoming_data_frame_expectations();
    find_client_device_expectations();
    mock().expectOneCall("test_device_unregistation_success_handler");
    receive_incoming_data_frame(active_connection, "{\"id\":\"2\",\"jsonrpc\":\"2.0\",\"result\":\"ok\"}");
    mock().checkExpectations();
    delete value_pointer;
}

TEST(pt_device_2_with_connection, test_pt_unregister_device_failure)
{
    register_device(active_connection->client);
    void *my_userdata = (void *) 145;
    mh_expect_mutexing(&api_mutex);
    expect_msg_api_message();
    pt_device_unregister(active_connection_id,
                         "test-device",
                         test_device_unregistation_success_handler,
                         test_device_unregistation_failure_handler,
                         my_userdata);
    ValuePointer *value_pointer = expect_outgoing_data_frame(
            "{\"id\":\"2\",\"jsonrpc\":\"2.0\",\"method\":\"device_unregister\","
            "\"params\":{\"deviceId\":\"test-device\"}}");
    process_event_loop_send_message(true /* connection found */);
    receive_incoming_data_frame_expectations();
    find_client_device_expectations();
    mock().expectOneCall("test_device_unregistation_failure_handler");
    receive_incoming_data_frame(active_connection,
                                "{\"id\":\"2\",\"jsonrpc\":\"2.0\",\"error\":{\"code\""
                                ":-30001,\"message\":\"Protocol translator not registered.\"}}");
    mock().checkExpectations();
    delete value_pointer;
}

TEST(pt_device_2_with_connection, test_pt_unregister_device_no_connection)
{
    register_device(active_connection->client);
    void *my_userdata = (void *) 145;

    mh_expect_mutexing(&api_mutex);
    pt_client_t *client = destroy_active_connection();
    pt_status_t status = pt_device_unregister(active_connection_id,
                                              "test-device",
                                              test_device_unregistation_success_handler,
                                              test_device_unregistation_failure_handler,
                                              my_userdata);
    CHECK_EQUAL(PT_STATUS_NOT_CONNECTED, status);
    destroy_client(client);
    mock().checkExpectations();
}

TEST(pt_device_2_with_connection, test_pt_unregister_device_not_found)
{
    register_device(active_connection->client);
    void *my_userdata = (void *) 145;

    mh_expect_mutexing(&api_mutex);
    pt_status_t status = pt_device_unregister(active_connection_id,
                                              "test-device-not-exist",
                                              test_device_unregistation_success_handler,
                                              test_device_unregistation_failure_handler,
                                              my_userdata);
    CHECK_EQUAL(PT_STATUS_NOT_FOUND, status);
    mock().checkExpectations();
}

static void pt_devices_registration_success_cb(connection_id_t connection_id, void *userdata)
{
    mock().actualCall("pt_devices_registration_success_cb");
}

static void pt_devices_registration_failure_cb(connection_id_t connection_id, void *userdata)
{
    mock().actualCall("pt_devices_registration_failure_cb");
}

static void pt_devices_unregistration_success_cb(connection_id_t connection_id, void *userdata)
{
    mock().actualCall("pt_devices_unregistration_success_cb");
}

static void pt_devices_unregistration_failure_cb(connection_id_t connection_id, void *userdata)
{
    mock().actualCall("pt_devices_unregistration_failure_cb");
}

static devices_test_data_t *create_devices_data_when_connected()
{
    CHECK(active_connection_id != PT_API_CONNECTION_ID_INVALID);
    devices_test_data_t *devices_data = (devices_test_data_t *) calloc(1, sizeof(devices_test_data_t));
    devices_data->client = active_connection->client;
    return devices_data;
}

static devices_test_data_t *register_devices(bool one_fails)
{
    devices_test_data_t *devices_data = create_devices_data_when_connected();
    void *my_userdata = (void *) 125;
    create_test_device("digital-thermometer");
    create_test_device("analog-thermometer");
    mh_expect_mutexing(&api_mutex);
    expect_msg_api_message();
    expect_msg_api_message();

    pt_status_t status = pt_devices_register_devices(active_connection_id,
                                                     pt_devices_registration_success_cb,
                                                     pt_devices_registration_failure_cb,
                                                     my_userdata);
    CHECK_EQUAL(PT_STATUS_SUCCESS, status);

    devices_data->register_value_pointer1 = expect_outgoing_data_frame(
            "{\"id\":\"1\",\"jsonrpc\":\"2.0\",\"method\":\"device_register\",\"params\":{\"deviceId\":\"digital-"
            "thermometer\",\"lifetime\":3600,\"objects\":[{\"objectId\":3303,\"objectInstances\":[{"
            "\"objectInstanceId\":1,\"resources\":[{\"operations\":1,\"resourceId\":5601,\"type\":\"opaque\",\"value\":"
            "\"\"}]}]}],\"queuemode\":\"-\"}}");
    process_event_loop_send_message(true /* connection found */);
    devices_data->register_value_pointer2 = expect_outgoing_data_frame(
            "{\"id\":\"2\",\"jsonrpc\":\"2.0\",\"method\":\"device_register\",\"params\":{\"deviceId\":\"analog-"
            "thermometer\",\"lifetime\":3600,\"objects\":[{\"objectId\":3303,\"objectInstances\":[{"
            "\"objectInstanceId\":1,\"resources\":[{\"operations\":1,\"resourceId\":5601,\"type\":\"opaque\",\"value\":"
            "\"\"}]}]}],\"queuemode\":\"-\"}}");
    process_event_loop_send_message(true /* connection found */);
    mock().checkExpectations();
    receive_incoming_data_frame_expectations();
    find_client_device_expectations();
    receive_incoming_data_frame(active_connection, "{\"id\":\"1\",\"jsonrpc\":\"2.0\",\"result\":\"ok\"}");
    receive_incoming_data_frame_expectations();
    find_client_device_expectations();
    if (!one_fails) {
        mock().expectOneCall("pt_devices_registration_success_cb");
        receive_incoming_data_frame(active_connection, "{\"id\":\"2\",\"jsonrpc\":\"2.0\",\"result\":\"ok\"}");
    } else {
        mock().expectOneCall("pt_devices_registration_failure_cb");
        receive_incoming_data_frame(active_connection,
                                    "{\"id\":\"2\",\"jsonrpc\":\"2.0\",\"error\":{\"code\":-30005,\"message\":\"Cannot "
                                    "register endpoint, because it's "
                                    "already registered.\"}}");
    }
    return devices_data;
}

static void test_register_device_complex(bool registration_succeeds,
                                         bool unregistration_succeeds,
                                         bool delete_before_registration_completes,
                                         bool delete_before_unregistration_completes)
{

    devices_test_data_t *devices_data = create_devices_data_when_connected();
    void *my_userdata = (void *) 125;
    const char *objlink = "test-device-id/3/0/5700";
    const char *test_string = "testing-123";
    uint8_t *temperature = (uint8_t *) strdup("1000k");

    int32_t int_value = 314156;
    int32_t *int_value_ptr = (int32_t *) malloc(sizeof(int32_t));
    memcpy(int_value_ptr, &int_value, sizeof(int32_t));

    int32_t time_value = 314157;
    int32_t *time_value_ptr = (int32_t *) malloc(sizeof(int32_t));
    memcpy(time_value_ptr, &time_value, sizeof(int32_t));

    float float_value = 314156;
    float *float_value_ptr = (float *) malloc(sizeof(float));
    memcpy(float_value_ptr, &float_value, sizeof(float));

    static bool always_true = true;

    create_test_device("test-device-id");
    pt_status_t status;
    mh_expect_mutexing(&api_mutex);
    status = pt_device_add_resource(active_connection->id,
                                    "test-device-id",
                                    3,
                                    0,
                                    5700,
                                    /* resource name */ NULL,
                                    LWM2M_OPAQUE,
                                    temperature,
                                    strlen((char *) temperature),
                                    free);
    mh_expect_mutexing(&api_mutex);
    status = pt_device_add_resource(active_connection->id,
                                    "test-device-id",
                                    3,
                                    0,
                                    5701,
                                    /* resource name */ NULL,
                                    LWM2M_STRING,
                                    (uint8_t *) strdup(test_string),
                                    strlen(test_string),
                                    free);
    mh_expect_mutexing(&api_mutex);
    status = pt_device_add_resource(active_connection->id,
                                    "test-device-id",
                                    3,
                                    0,
                                    5702,
                                    /* resource name */ NULL,
                                    LWM2M_INTEGER,
                                    (uint8_t *) int_value_ptr,
                                    sizeof(int32_t),
                                    free);
    mh_expect_mutexing(&api_mutex);
    status = pt_device_add_resource(active_connection->id,
                                    "test-device-id",
                                    3,
                                    0,
                                    5703,
                                    /* resource name */ NULL,
                                    LWM2M_FLOAT,
                                    (uint8_t *) float_value_ptr,
                                    sizeof(float),
                                    free);
    mh_expect_mutexing(&api_mutex);
    status = pt_device_add_resource(active_connection->id,
                                    "test-device-id",
                                    3,
                                    0,
                                    5704,
                                    /* resource name */ NULL,
                                    LWM2M_BOOLEAN,
                                    (uint8_t *) &always_true,
                                    sizeof(bool),
                                    NULL);
    mh_expect_mutexing(&api_mutex);
    status = pt_device_add_resource(active_connection->id,
                                    "test-device-id",
                                    3,
                                    0,
                                    5705,
                                    /* resource name */ NULL,
                                    LWM2M_TIME,
                                    (uint8_t *) time_value_ptr,
                                    sizeof(int32_t),
                                    free);
    mh_expect_mutexing(&api_mutex);
    status = pt_device_add_resource(active_connection->id,
                                    "test-device-id",
                                    3,
                                    0,
                                    5706,
                                    /* resource name */ NULL,
                                    LWM2M_OBJLINK,
                                    (uint8_t *) strdup(objlink),
                                    strlen(objlink),
                                    free);

    mh_expect_mutexing(&api_mutex);
    expect_msg_api_message();

    status = pt_devices_register_devices(active_connection_id,
                                         pt_devices_registration_success_cb,
                                         pt_devices_registration_failure_cb,
                                         my_userdata);
    CHECK_EQUAL(PT_STATUS_SUCCESS, status);

    devices_data->register_value_pointer1 = expect_outgoing_data_frame(
            "{\"id\":\"1\",\"jsonrpc\":\"2.0\",\"method\":\"device_register\",\"params\":{\"deviceId\":\"test-device-"
            "id\",\"lifetime\":3600,\"objects\":[{\"objectId\":3303,\"objectInstances\":[{\"objectInstanceId\":1,"
            "\"resources\":[{\"operations\":1,\"resourceId\":5601,\"type\":\"opaque\",\"value\":\"\"}]}]},{"
            "\"objectId\":3,\"objectInstances\":[{\"objectInstanceId\":0,\"resources\":[{\"operations\":1,"
            "\"resourceId\":5700,\"type\":\"opaque\",\"value\":\"MTAwMGs=\"},{\"operations\":1,\"resourceId\":5701,"
            "\"type\":\"string\",\"value\":\"dGVzdGluZy0xMjM=\"},{\"operations\":1,\"resourceId\":5702,\"type\":"
            "\"int\",\"value\":\"LMsEAA==\"},{\"operations\":1,\"resourceId\":5703,\"type\":\"float\",\"value\":"
            "\"gGWZSA==\"},{\"operations\":1,\"resourceId\":5704,\"type\":\"bool\",\"value\":\"AQ==\"},{\"operations\":"
            "1,\"resourceId\":5705,\"type\":\"time\",\"value\":\"LcsEAA==\"},{\"operations\":1,\"resourceId\":5706,"
            "\"type\":\"objlink\",\"value\":\"dGVzdC1kZXZpY2UtaWQvMy8wLzU3MDA=\"}]}]}],\"queuemode\":\"-\"}}");
    process_event_loop_send_message(true /* connection found */);
    mock().checkExpectations();
    if (delete_before_registration_completes) {
        pt_devices_t *devices = active_connection->client->devices;
        pt_device_t *device = pt_devices_find_device(devices, "test-device-id");
        pt_devices_remove_and_free_device(devices, device);
    }

    receive_incoming_data_frame_expectations();
    find_client_device_expectations();
    if (registration_succeeds) {
        mock().expectOneCall("pt_devices_registration_success_cb");
        receive_incoming_data_frame(active_connection, "{\"id\":\"1\",\"jsonrpc\":\"2.0\",\"result\":\"ok\"}");
    } else {
        mock().expectOneCall("pt_devices_registration_failure_cb");
        receive_incoming_data_frame(active_connection,
                                    "{\"id\":\"1\",\"jsonrpc\":\"2.0\",\"error\":{\"code\":-30005,\"message\":\"Cannot "
                                    "register endpoint, because it's "
                                    "already registered.\"}}");
    }

    mh_expect_mutexing(&api_mutex);

    if (!delete_before_registration_completes) {
        expect_msg_api_message();
    }
    status = pt_devices_unregister_devices(active_connection_id,
                                           pt_devices_unregistration_success_cb,
                                           pt_devices_unregistration_failure_cb,
                                           my_userdata);

    if (!delete_before_registration_completes) {
        CHECK_EQUAL(PT_STATUS_SUCCESS, status);
        devices_data->register_value_pointer2 = expect_outgoing_data_frame(
                "{\"id\":\"2\",\"jsonrpc\":\"2.0\",\"method\":\"device_unregister\",\"params\":{\"deviceId\":\"test-"
                "device-"
                "id\"}}");

        if (delete_before_unregistration_completes) {
            pt_devices_t *devices = active_connection->client->devices;
            pt_device_t *device = pt_devices_find_device(devices, "test-device-id");
            pt_devices_remove_and_free_device(devices, device);
        }

        process_event_loop_send_message(true /* connection found */);
        receive_incoming_data_frame_expectations();
        find_client_device_expectations();
        if (unregistration_succeeds) {
            mock().expectOneCall("pt_devices_unregistration_success_cb");
            receive_incoming_data_frame(active_connection, "{\"id\":\"2\",\"jsonrpc\":\"2.0\",\"result\":\"ok\"}");
        } else {
            mock().expectOneCall("pt_devices_unregistration_failure_cb");
            receive_incoming_data_frame(active_connection,
                                        "{\"id\":\"2\",\"jsonrpc\":\"2.0\",\"error\":{\"code\":-30000,\"message\":"
                                        "\"Protocol API internal error.\"}}");
        }
    } else {
        CHECK_EQUAL(PT_STATUS_UNNECESSARY, status);
    }

    free_devices_data(devices_data);
}

TEST(pt_device_2_with_connection, test_register_device_complex_base_case)
{
    test_register_device_complex(true /*registration succeeds */,
                                 true /*unregistration succeeds */,
                                 false /* delete before registration completes */,
                                 false /* delete before unregistration completes */);
    mock().checkExpectations();
}

TEST(pt_device_2_with_connection, test_register_device_delete_before_registration_succeeds)
{
    test_register_device_complex(true /*registration succeeds */,
                                 true /*unregistration succeeds */,
                                 true /* delete before registration completes */,
                                 false /* delete before unregistration completes */);
    mock().checkExpectations();
}

TEST(pt_device_2_with_connection, test_register_device_delete_before_unregistration_succeeds)
{
    test_register_device_complex(true /*registration succeeds */,
                                 true /*unregistration succeeds */,
                                 false /* delete before registration completes */,
                                 true /* delete before unregistration completes */);
    mock().checkExpectations();
}

TEST(pt_device_2_with_connection, test_register_device_delete_before_registration_fails)
{
    test_register_device_complex(false /*registration succeeds */,
                                 true /*unregistration succeeds */,
                                 true /* delete before registration completes */,
                                 false /* delete before unregistration completes */);
    mock().checkExpectations();
}

TEST(pt_device_2_with_connection, test_register_device_delete_before_unregistration_fails)
{
    test_register_device_complex(true /*registration succeeds */,
                                 false /*unregistration succeeds */,
                                 false /* delete before registration completes */,
                                 true /* delete before unregistration completes */);
    mock().checkExpectations();
}

static void unregister_devices(devices_test_data_t *devices_data, bool one_fails)
{
    void *my_userdata = (void *) 225;
    mh_expect_mutexing(&api_mutex);
    expect_msg_api_message();
    expect_msg_api_message();
    pt_devices_unregister_devices(active_connection_id,
                                  pt_devices_unregistration_success_cb,
                                  pt_devices_unregistration_failure_cb,
                                  my_userdata);
    devices_data->unregister_value_pointer1 = expect_outgoing_data_frame(
            "{\"id\":\"3\",\"jsonrpc\":\"2.0\",\"method\":\"device_unregister\",\"params\":{\"deviceId\":\"digital-"
            "thermometer\"}}");
    process_event_loop_send_message(true /* connection found */);
    devices_data->unregister_value_pointer2 = expect_outgoing_data_frame(
            "{\"id\":\"4\",\"jsonrpc\":\"2.0\",\"method\":\"device_unregister\",\"params\":{\"deviceId\":\"analog-"
            "thermometer\"}}");
    process_event_loop_send_message(true /* connection found */);
    mock().checkExpectations();
    receive_incoming_data_frame_expectations();
    find_client_device_expectations();
    receive_incoming_data_frame(active_connection, "{\"id\":\"3\",\"jsonrpc\":\"2.0\",\"result\":\"ok\"}");
    receive_incoming_data_frame_expectations();
    find_client_device_expectations();
    if (!one_fails) {
        mock().expectOneCall("pt_devices_unregistration_success_cb");
        receive_incoming_data_frame(active_connection, "{\"id\":\"4\",\"jsonrpc\":\"2.0\",\"result\":\"ok\"}");
    } else {
        mock().expectOneCall("pt_devices_unregistration_failure_cb");
        receive_incoming_data_frame(active_connection,
                                    "{\"id\":\"4\",\"jsonrpc\":\"2.0\",\"error\":{\"code\":-30001,\"message\":"
                                    "\"Protocol translator not registered.\"}}");
    }
}

TEST(pt_device_2, test_pt_device_create_with_userdata_no_device_id)
{
    pt_status_t status = pt_device_create(314, NULL, 3600, NONE);
    CHECK_EQUAL(PT_STATUS_INVALID_PARAMETERS, status);
    mock().checkExpectations();
}

TEST(pt_device_2, test_pt_device_create_with_userdata_no_connection)
{
    mh_expect_mutexing(&api_mutex);
    pt_status_t status = pt_device_create(313, "test-device", 3600, NONE);
    CHECK_EQUAL(PT_STATUS_NOT_CONNECTED, status);
    mock().checkExpectations();
}

TEST(pt_device_2_with_connection, test_pt_device_create_with_no_duplicates)
{
    pt_status_t status;
    mh_expect_mutexing(&api_mutex);
    status = pt_device_create(active_connection->id, "test-device-id", 3600, NONE);
    CHECK_EQUAL(PT_STATUS_SUCCESS, status);
    mh_expect_mutexing(&api_mutex);
    status = pt_device_create(active_connection->id, "test-device-id", 3600, NONE);
    CHECK_EQUAL(PT_STATUS_ITEM_EXISTS, status);
    mock().checkExpectations();
}

TEST(pt_device_2_with_connection, test_pt_devices_register_devices_no_devices)
{
    void *my_userdata = (void *) 325;
    devices_test_data_t *devices_data = create_devices_data_when_connected();
    mh_expect_mutexing(&api_mutex);
    pt_status_t status = pt_devices_register_devices(active_connection_id,
                                                     pt_devices_registration_success_cb,
                                                     pt_devices_registration_failure_cb,
                                                     my_userdata);
    CHECK_EQUAL(PT_STATUS_UNNECESSARY, status);
    mock().checkExpectations();
    free_devices_data(devices_data);
}

TEST(pt_device_2_with_connection, test_pt_devices_unregister_devices_no_devices)
{
    void *my_userdata = (void *) 326;
    devices_test_data_t *devices_data = create_devices_data_when_connected();
    mh_expect_mutexing(&api_mutex);
    pt_status_t status = pt_devices_unregister_devices(active_connection_id,
                                                       pt_devices_registration_success_cb,
                                                       pt_devices_registration_failure_cb,
                                                       my_userdata);
    CHECK_EQUAL(PT_STATUS_UNNECESSARY, status);
    mock().checkExpectations();
    free_devices_data(devices_data);
}

TEST(pt_device_2_with_connection, test_pt_devices_register_devices)
{
    devices_test_data_t *devices_data = register_devices(false /* one fails */);
    mock().checkExpectations();
    free_devices_data(devices_data);
}

TEST(pt_device_2_with_connection, test_pt_devices_register_devices_one_fails)
{
    devices_test_data_t *devices_data = register_devices(true /* one fails */);
    mock().checkExpectations();
    free_devices_data(devices_data);
}

TEST(pt_device_2_with_connection, test_pt_devices_unregister_devices_success)
{
    devices_test_data_t *devices_data = register_devices(false /* one fails */);
    unregister_devices(devices_data, false /* one fails */);
    mock().checkExpectations();
    free_devices_data(devices_data);
}

TEST(pt_device_2_with_connection, test_pt_devices_unregister_devices_failure)
{
    devices_test_data_t *devices_data = register_devices(false /* one fails */);
    unregister_devices(devices_data, true /* one fails */);
    mock().checkExpectations();
    free_devices_data(devices_data);
}

static void pt_devices_update_success_cb(connection_id_t connection_id, void *userdata)
{
    mock().actualCall("pt_devices_update_success_cb");
}

static void pt_devices_update_failure_cb(connection_id_t connection_id, void *userdata)
{
    mock().actualCall("pt_devices_update_failure_cb");
}

TEST(pt_device_2_with_connection, test_pt_devices_update_no_changes)
{
    void *my_userdata = (void *) 126;
    devices_test_data_t *devices_data = register_devices(false /* one fails */);
    mh_expect_mutexing(&api_mutex);
    pt_status_t status = pt_devices_update(active_connection_id,
                                           pt_devices_update_success_cb,
                                           pt_devices_update_failure_cb,
                                           my_userdata);
    CHECK_EQUAL(PT_STATUS_UNNECESSARY, status);

    mock().checkExpectations();
    free_devices_data(devices_data);
}

static void test_write_values_success(connection_id_t connection_id, const char *device_id, void *userdata)
{
    mock().actualCall("test_write_values_success").withStringParameter("device_id", device_id);
}

static void test_write_values_failure(connection_id_t connection_id, const char *device_id, void *userdata)
{
    mock().actualCall("test_write_values_failure").withStringParameter("device_id", device_id);
}

TEST(pt_device_2_with_connection, test_pt_device_write_values_device_null)
{
    void *my_userdata = (void *) 926;
    devices_test_data_t *devices_data = register_devices(false /* one fails */);
    pt_status_t status = pt_device_write_values((const connection_id_t) active_connection_id,
                                                NULL,
                                                test_write_values_success,
                                                test_write_values_failure,
                                                my_userdata);
    CHECK_EQUAL(PT_STATUS_INVALID_PARAMETERS, status);

    mock().checkExpectations();
    free_devices_data(devices_data);
}

TEST(pt_device_2_with_connection, test_pt_device_write_values_success)
{
    void *my_userdata = (void *) 926;
    devices_test_data_t *devices_data = register_devices(false /* one fails */);
    mh_expect_mutexing(&api_mutex);
    expect_msg_api_message();

    pt_status_t status = pt_device_write_values((const connection_id_t) active_connection_id,
                                                "digital-thermometer",
                                                test_write_values_success,
                                                test_write_values_failure,
                                                my_userdata);
    CHECK_EQUAL(PT_STATUS_SUCCESS, status);
    ValuePointer *value_pointer1 = expect_outgoing_data_frame(
            "{\"id\":\"3\",\"jsonrpc\":\"2.0\",\"method\":\"write\",\"params\":{\"deviceId\":\"digital-thermometer\","
            "\"objects\":[]}}");
    process_event_loop_send_message(true /* connection found */);
    mock().checkExpectations();
    receive_incoming_data_frame_expectations();
    find_client_device_expectations();
    mock().expectOneCall("test_write_values_success").withStringParameter("device_id", "digital-thermometer");
    receive_incoming_data_frame(active_connection, "{\"id\":\"3\",\"jsonrpc\":\"2.0\",\"result\":\"ok\"}");

    mock().checkExpectations();
    free_devices_data(devices_data);
    delete value_pointer1;
}

TEST(pt_device_2_with_connection, test_pt_device_write_values_no_connection)
{
    void *my_userdata = (void *) 929;
    devices_test_data_t *devices_data = register_devices(false /* one fails */);
    mh_expect_mutexing(&api_mutex);

    pt_status_t status = pt_device_write_values((const connection_id_t) PT_API_CONNECTION_ID_INVALID,
                                                "digital-thermometer",
                                                test_write_values_success,
                                                test_write_values_failure,
                                                my_userdata);
    CHECK_EQUAL(PT_STATUS_NOT_CONNECTED, status);
    free_devices_data(devices_data);
}

TEST(pt_device_2_with_connection, test_pt_device_write_values_api_message_sending_fails)
{
    void *my_userdata = (void *) 926;
    devices_test_data_t *devices_data = register_devices(false /* one fails */);
    expect_msg_api_message_sending_fails();

    mh_expect_mutexing(&api_mutex);
    pt_status_t status = pt_device_write_values((const connection_id_t) active_connection_id,
                                                "digital-thermometer",
                                                test_write_values_success,
                                                test_write_values_failure,
                                                my_userdata);
    CHECK_EQUAL(PT_STATUS_ERROR, status);
    mock().checkExpectations();
    free_devices_data(devices_data);
}

static void test_writing_values(
        bool write_fails,
        bool no_connection, /* specifies if there should be no connection at all when API function is called */
        bool connection_found /* flag controlling if connection is available when write_data_frame is called */)
{
    void *my_userdata = (void *) 127;
    devices_test_data_t *devices_data = register_devices(false /* one fails */);
    pt_client_t *client = NULL;
    char *temperature = strdup("100K");

    if (no_connection) {
        client = destroy_active_connection();
    }

    mh_expect_mutexing(&api_mutex);
    pt_status_t status = pt_device_set_resource_value(active_connection_id,
                                                      "analog-thermometer",
                                                      TEMPERATURE_SENSOR,
                                                      1,
                                                      MIN_MEASURED_VALUE,
                                                      (uint8_t *) temperature,
                                                      strlen(temperature),
                                                      free);
    if (!no_connection) {
        CHECK_EQUAL(PT_STATUS_SUCCESS, status);
        mh_expect_mutexing(&api_mutex);
        expect_msg_api_message();
        status = pt_devices_update(active_connection_id,
                                   pt_devices_update_success_cb,
                                   pt_devices_update_failure_cb,
                                   my_userdata);
        CHECK_EQUAL(PT_STATUS_SUCCESS, status);
        ValuePointer *vp = NULL;
        mock().checkExpectations();
        if (!connection_found) {
            client = destroy_active_connection();
            mock().expectOneCall("pt_devices_update_failure_cb");
        } else {
            vp = expect_outgoing_data_frame(
                    "{\"id\":\"3\",\"jsonrpc\":\"2.0\",\"method\":\"write\",\"params\":{\"deviceId\":\"analog-"
                    "thermometer\","
                    "\"objects\":[{\"objectId\":3303,\"objectInstances\":[{\"objectInstanceId\":1,\"resources\":[{"
                    "\"operations\":1,\"resourceId\":5601,\"type\":\"opaque\",\"value\":\"MTAwSw==\"}]}]}]}}");
        }
        process_event_loop_send_message(connection_found);
        if (connection_found) {
            receive_incoming_data_frame_expectations();
            if (!write_fails) {
                find_client_device_expectations();
                mock().expectOneCall("pt_devices_update_success_cb");
                receive_incoming_data_frame(active_connection, "{\"id\":\"3\",\"jsonrpc\":\"2.0\",\"result\":\"ok\"}");
            } else {
                mock().expectOneCall("pt_devices_update_failure_cb");
                receive_incoming_data_frame(active_connection,
                                            "{\"id\":\"3\",\"jsonrpc\":\"2.0\",\"error\":{\"code\""
                                            ":-30001,\"message\":\"Protocol translator not registered.\"}}");
            }
        }
        mock().checkExpectations();
        delete vp;
    } else { // no_connection
        CHECK_EQUAL(PT_STATUS_NOT_CONNECTED, status);
    }
    if (client) {
        destroy_client(client);
    }
    free_devices_data(devices_data);
}

TEST(pt_device_2_with_connection, test_pt_devices_update_some_changes_response_success)
{
    test_writing_values(false /* write fails */, false /* no connection */, true /* connection found */);
    mock().checkExpectations();
}

TEST(pt_device_2_with_connection, test_pt_devices_update_some_changes_response_failure)
{
    test_writing_values(true /* write fails */, false /* no connection */, true /* connection found */);
    mock().checkExpectations();
}

TEST(pt_device_2_with_connection, test_pt_devices_update_some_changes_response_connection_lost)
{
    test_writing_values(false /* write fails */, false /* no connection */, false /* connection found */);
    mock().checkExpectations();
}

TEST(pt_device_2_with_connection, test_pt_device_write_value_no_connection)
{
    test_writing_values(false /* write fails */, true /* no connection */, false /* connection found */);
    mock().checkExpectations();
}

TEST(pt_device_2_with_connection, test_pt_device_set_resource_value_device_not_found)
{
    devices_test_data_t *devices_data = register_devices(false /* one fails */);
    char *temperature = strdup("100K");

    mh_expect_mutexing(&api_mutex);
    pt_status_t status = pt_device_set_resource_value(active_connection_id,
                                                      "not-found-thermometer",
                                                      TEMPERATURE_SENSOR,
                                                      1,
                                                      MIN_MEASURED_VALUE,
                                                      (uint8_t *) temperature,
                                                      strlen(temperature),
                                                      free);
    CHECK_EQUAL(PT_STATUS_NOT_FOUND, status);
    mock().checkExpectations();
    free_devices_data(devices_data);
}

TEST(pt_device_2_with_connection, test_pt_device_set_resource_value_resource_not_found)
{
    devices_test_data_t *devices_data = register_devices(false /* one fails */);
    char *temperature = strdup("100K");

    mh_expect_mutexing(&api_mutex);
    pt_status_t status = pt_device_set_resource_value(active_connection_id,
                                                      "analog-thermometer",
                                                      TEMPERATURE_SENSOR,
                                                      1,
                                                      MAX_MEASURED_VALUE,
                                                      (uint8_t *) temperature,
                                                      strlen(temperature),
                                                      free);
    CHECK_EQUAL(PT_STATUS_NOT_FOUND, status);
    mock().checkExpectations();
    free_devices_data(devices_data);
}

TEST(pt_device_2_with_connection, test_pt_device_test_get_resource_value)
{
    devices_test_data_t *devices_data = register_devices(false /* one fails */);
    char *temperature = NULL;
    uint32_t temperature_len;

    mh_expect_mutexing(&api_mutex);
    pt_status_t status = pt_device_get_resource_value(active_connection_id,
                                                      "analog-thermometer",
                                                      TEMPERATURE_SENSOR,
                                                      1,
                                                      MIN_MEASURED_VALUE,
                                                      (uint8_t **) &temperature,
                                                      &temperature_len);
    CHECK_EQUAL(PT_STATUS_SUCCESS, status);
    CHECK(NULL == temperature);
    CHECK(0 == temperature_len);

    char *temperature_out = strdup("100K");

    mh_expect_mutexing(&api_mutex);
    status = pt_device_set_resource_value(active_connection_id,
                                          "analog-thermometer",
                                          TEMPERATURE_SENSOR,
                                          1,
                                          MIN_MEASURED_VALUE,
                                          (uint8_t *) temperature_out,
                                          strlen(temperature_out) + 1,
                                          free);

    mh_expect_mutexing(&api_mutex);
    status = pt_device_get_resource_value(active_connection_id,
                                          "analog-thermometer",
                                          TEMPERATURE_SENSOR,
                                          1,
                                          MIN_MEASURED_VALUE,
                                          (uint8_t **) &temperature,
                                          &temperature_len);
    CHECK_EQUAL(PT_STATUS_SUCCESS, status);
    STRCMP_EQUAL("100K", temperature);
    CHECK(5 == temperature_len);

    mock().checkExpectations();
    free_devices_data(devices_data);
}

TEST(pt_device_2_with_connection, test_pt_device_test_get_resource_value_invalid_params)
{
    devices_test_data_t *devices_data = register_devices(false /* one fails */);
    uint32_t temperature_len;

    mh_expect_mutexing(&api_mutex);
    pt_status_t status = pt_device_get_resource_value(active_connection_id,
                                                      "analog-thermometer",
                                                      TEMPERATURE_SENSOR,
                                                      1,
                                                      MIN_MEASURED_VALUE,
                                                      (uint8_t **) NULL,
                                                      &temperature_len);
    CHECK_EQUAL(PT_STATUS_INVALID_PARAMETERS, status);

    mock().checkExpectations();
    free_devices_data(devices_data);
}

TEST(pt_device_2_with_connection, test_pt_device_test_get_resource_value_no_connection)
{
    devices_test_data_t *devices_data = register_devices(false /* one fails */);
    char *temperature = NULL;
    uint32_t temperature_len;

    pt_client_t *client = destroy_active_connection();
    mh_expect_mutexing(&api_mutex);
    pt_status_t status = pt_device_get_resource_value(active_connection_id,
                                                      "analog-thermometer",
                                                      TEMPERATURE_SENSOR,
                                                      1,
                                                      MIN_MEASURED_VALUE,
                                                      (uint8_t **) &temperature,
                                                      &temperature_len);
    CHECK_EQUAL(PT_STATUS_NOT_CONNECTED, status);
    CHECK(NULL == temperature);
    CHECK(0 == temperature_len);
    mock().checkExpectations();
    free_devices_data(devices_data);
    destroy_client(client);
}

TEST(pt_device_2_with_connection, test_pt_device_test_get_resource_value_device_name_typo)
{
    devices_test_data_t *devices_data = register_devices(false /* one fails */);
    char *temperature = NULL;
    uint32_t temperature_len;

    mh_expect_mutexing(&api_mutex);
    pt_status_t status = pt_device_get_resource_value(active_connection_id,
                                                      "analog-thermmometer",
                                                      TEMPERATURE_SENSOR,
                                                      1,
                                                      MIN_MEASURED_VALUE,
                                                      (uint8_t **) &temperature,
                                                      &temperature_len);
    CHECK_EQUAL(PT_STATUS_NOT_FOUND, status);
    CHECK(NULL == temperature);
    CHECK(0 == temperature_len);

    mock().checkExpectations();
    free_devices_data(devices_data);
}

TEST(pt_device_2_with_connection, test_pt_device_test_get_resource_value_resource_not_found)
{
    devices_test_data_t *devices_data = register_devices(false /* one fails */);
    char *temperature = NULL;
    uint32_t temperature_len;

    mh_expect_mutexing(&api_mutex);
    pt_status_t status = pt_device_get_resource_value(active_connection_id,
                                                      "analog-thermometer",
                                                      TEMPERATURE_SENSOR,
                                                      1,
                                                      MAX_MEASURED_VALUE,
                                                      (uint8_t **) &temperature,
                                                      &temperature_len);
    CHECK_EQUAL(PT_STATUS_NOT_FOUND, status);
    CHECK(NULL == temperature);
    CHECK(0 == temperature_len);

    mock().checkExpectations();
    free_devices_data(devices_data);
}

static void test_event_loop_callback(void *data)
{
    mock().actualCall("test_event_loop_callback").withPointerParameter("data", data);
}

TEST(pt_device_2_with_connection, test_pt_api_send_to_event_loop_with_not_found_connection)
{
    mh_expect_mutexing(&api_mutex);
    CHECK_EQUAL(PT_STATUS_NOT_CONNECTED, pt_api_send_to_event_loop(1000, NULL, test_event_loop_callback));
    mock().checkExpectations();
}

static void process_event_loop_test_message()
{
    event_loop_message_t *msg = mock_msg_api_pop_message();
    if (NULL == msg) {
        CHECK(1 != 1); // place breakpoint on this line for debugging
    }
    CHECK(test_event_loop_callback == msg->callback);
    msg->callback(msg->data);
    free(msg);
}

TEST(pt_device_2_with_connection, test_pt_api_send_to_event_loop_with_found_connection_success)
{
    mh_expect_mutexing(&api_mutex);
    mock().expectOneCall("msg_api_send_message").andReturnValue(true);
    mock().expectOneCall("test_event_loop_callback").withPointerParameter("data", (void *) 0x123);
    CHECK_EQUAL(PT_STATUS_SUCCESS,
                pt_api_send_to_event_loop(active_connection->id, (void *) 0x123, test_event_loop_callback));
    process_event_loop_test_message();
    mock().checkExpectations();
}

TEST(pt_device_2_with_connection, test_pt_api_send_to_event_loop_with_found_connection_fail)
{
    expect_msg_api_message_sending_fails();
    CHECK_EQUAL(PT_STATUS_ERROR, pt_api_send_to_event_loop(active_connection->id, NULL, test_event_loop_callback));
    mock().checkExpectations();
}

TEST(pt_device_2, test_get_next_free_object_instance_id_no_connection)
{
    CHECK(-1 == pt_device_get_next_free_object_instance_id(1, "test-device-id", 0));
    mock().checkExpectations();
}

TEST(pt_device_2_with_connection, test_get_next_free_object_instance_id)
{
    // No device, connection exist.
    CHECK(-1 == pt_device_get_next_free_object_instance_id(active_connection->id, "test-device-id", 3));

    // Device, object does not exist.
    pt_status_t status;
    mh_expect_mutexing(&api_mutex);
    status = pt_device_create(active_connection->id, "test-device-id", 3600, NONE);
    CHECK(PT_STATUS_SUCCESS == status);
    CHECK(0 == pt_device_get_next_free_object_instance_id(active_connection->id, "test-device-id", 3));

    // Device, object exist.
    mh_expect_mutexing(&api_mutex);
    status = pt_device_add_resource(active_connection->id, "test-device-id", 3, 0, 5700, /* resource name */ NULL, LWM2M_OPAQUE, NULL, 0, NULL);
    CHECK(PT_STATUS_SUCCESS == status);
    CHECK(1 == pt_device_get_next_free_object_instance_id(active_connection->id, "test-device-id", 3));
    mock().checkExpectations();
}

void test_device_success_handler_reg_data_allocation(const connection_id_t connection_id,
                                                     const char *device_id,
                                                     void *userdata)
{
}

void test_device_failure_handler_reg_data_allocation(const connection_id_t connection_id,
                                                     const char *device_id,
                                                     void *userdata)
{
}

TEST(pt_device_2, test_check_registration_data_allocated)
{
    CHECK(PT_STATUS_ALLOCATION_FAIL == check_registration_data_allocated(NULL, NULL, NULL, NULL, NULL, NULL, NULL));
    json_t *json = json_object();
    CHECK(PT_STATUS_ALLOCATION_FAIL == check_registration_data_allocated(json, NULL, NULL, NULL, NULL, NULL, NULL));
    json = json_object();
    CHECK(PT_STATUS_ALLOCATION_FAIL == check_registration_data_allocated(NULL, json, NULL, NULL, NULL, NULL, NULL));
    json = json_object();
    CHECK(PT_STATUS_ALLOCATION_FAIL == check_registration_data_allocated(NULL, NULL, json, NULL, NULL, NULL, NULL));
    json = json_object();
    CHECK(PT_STATUS_ALLOCATION_FAIL == check_registration_data_allocated(NULL, NULL, NULL, json, NULL, NULL, NULL));
    json = json_object();
    CHECK(PT_STATUS_ALLOCATION_FAIL == check_registration_data_allocated(NULL, NULL, NULL, NULL, json, NULL, NULL));
    json = json_object();
    CHECK(PT_STATUS_ALLOCATION_FAIL == check_registration_data_allocated(NULL, NULL, NULL, NULL, NULL, json, NULL));


    // Customer callback allocated
    char *data = strdup("dynamic-customer-data");
    pt_device_customer_callback_t
            *callback = allocate_device_customer_callback(1,
                                                          test_device_success_handler_reg_data_allocation,
                                                          test_device_failure_handler_reg_data_allocation,
                                                          "test-device-id",
                                                          data);
    CHECK(PT_STATUS_ALLOCATION_FAIL == check_registration_data_allocated(NULL, NULL, NULL, NULL, NULL, NULL, callback));

    json_t *msg = json_object();
    json_t *params = json_object();
    json_t *objects = json_object();
    json_t *device_lifetime = json_object();
    json_t *device_queuemode = json_object();
    json_t *device_id = json_object();
    callback = allocate_device_customer_callback(1,
                                                 test_device_success_handler_reg_data_allocation,
                                                 test_device_failure_handler_reg_data_allocation,
                                                 "test-device-id",
                                                 data);
    CHECK(PT_STATUS_SUCCESS == check_registration_data_allocated(msg,
                                                                 params,
                                                                 objects,
                                                                 device_lifetime,
                                                                 device_queuemode,
                                                                 device_id,
                                                                 callback));

    mock().checkExpectations();
    json_decref(msg);
    json_decref(params);
    json_decref(objects);
    json_decref(device_lifetime);
    json_decref(device_queuemode);
    json_decref(device_id);
    device_customer_callback_free(callback);
    free(data);
}

TEST(pt_device_2, test_check_unregister_data_allocated)
{
    CHECK(PT_STATUS_ALLOCATION_FAIL == check_unregistration_data_allocated(NULL, NULL, NULL, NULL));
    json_t *json = json_object();
    CHECK(PT_STATUS_ALLOCATION_FAIL == check_unregistration_data_allocated(json, NULL, NULL, NULL));
    json = json_object();
    CHECK(PT_STATUS_ALLOCATION_FAIL == check_unregistration_data_allocated(NULL, json, NULL, NULL));
    json = json_object();
    CHECK(PT_STATUS_ALLOCATION_FAIL == check_unregistration_data_allocated(NULL, NULL, json, NULL));

    char *data = strdup("dynamic-customer-data");
    pt_device_customer_callback_t
            *callback = allocate_device_customer_callback(1,
                                                          test_device_success_handler_reg_data_allocation,
                                                          test_device_failure_handler_reg_data_allocation,
                                                          "test-device-id",
                                                          data);
    CHECK(PT_STATUS_ALLOCATION_FAIL == check_unregistration_data_allocated(NULL, NULL, NULL, callback));

    json_t *msg = json_object();
    json_t *params = json_object();
    json_t *device_id = json_object();
    callback = allocate_device_customer_callback(1,
                                                 test_device_success_handler_reg_data_allocation,
                                                 test_device_failure_handler_reg_data_allocation,
                                                 "test-device-id",
                                                 data);

    CHECK(PT_STATUS_SUCCESS == check_unregistration_data_allocated(msg, params, device_id, callback));

    mock().checkExpectations();
    json_decref(msg);
    json_decref(params);
    json_decref(device_id);
    device_customer_callback_free(callback);
    free(data);
}

static pt_status_t dummy_resource_callback(const connection_id_t connection_id,
                                           const char *device_id,
                                           const uint16_t object_id,
                                           const uint16_t object_instance_id,
                                           const uint16_t resource_id,
                                           const uint8_t operation,
                                           const uint8_t *value,
                                           const uint32_t size,
                                           void *userdata)
{
    return (pt_status_t) mock().actualCall("dummy_resource_callback").returnIntValue();
}

TEST(pt_device_2_with_connection, test_pt_device_add_resource_with_callback_not_connected)
{
    uint8_t *temperature = (uint8_t *) strdup("1000k");

    mh_expect_mutexing(&api_mutex);
    pt_status_t status = pt_device_add_resource_with_callback(active_connection_id + 1,
                                         "analog-thermometer-typoed",
                                         TEMPERATURE_SENSOR,
                                         1,
                                         MAX_MEASURED_VALUE,
                                         /* resource name */ NULL,
                                         LWM2M_OPAQUE,
                                         OPERATION_WRITE,
                                         temperature,
                                         strlen((char *) temperature) + 1,
                                         free,
                                         dummy_resource_callback);
    CHECK_EQUAL(PT_STATUS_NOT_CONNECTED, status);
    mock().checkExpectations();
}

TEST(pt_device_2_with_connection, test_pt_device_add_resource_with_callback_not_found)
{
    uint8_t *temperature = (uint8_t *) strdup("1000k");

    mh_expect_mutexing(&api_mutex);
    pt_status_t status = pt_device_add_resource_with_callback(active_connection_id,
                                                              "analog-thermometer-typoed",
                                                              TEMPERATURE_SENSOR,
                                                              1,
                                                              MAX_MEASURED_VALUE,
                                                              /* resource name */ NULL,
                                                              LWM2M_OPAQUE,
                                                              OPERATION_WRITE,
                                                              temperature,
                                                              strlen((char *) temperature) + 1,
                                                              free,
                                                              dummy_resource_callback);
    CHECK_EQUAL(PT_STATUS_NOT_FOUND, status);
    mock().checkExpectations();
}

TEST(pt_device_2_with_connection, test_pt_device_add_resource_with_callback_already_found)
{
    uint8_t *temperature = (uint8_t *) strdup("1000k");
    uint8_t *temperature2 = (uint8_t *) strdup("2000k");
    pt_status_t status;
    devices_test_data_t *devices_data = register_devices(false /* one fails */);

    mh_expect_mutexing(&api_mutex);
    status = pt_device_add_resource_with_callback(active_connection_id,
                                                  "analog-thermometer",
                                                  TEMPERATURE_SENSOR,
                                                  1,
                                                  MAX_MEASURED_VALUE,
                                                  /* resource name */ NULL,
                                                  LWM2M_OPAQUE,
                                                  OPERATION_WRITE,
                                                  temperature,
                                                  strlen((char *) temperature) + 1,
                                                  free,
                                                  dummy_resource_callback);
    CHECK_EQUAL(PT_STATUS_SUCCESS, status);

    mh_expect_mutexing(&api_mutex);
    status = pt_device_add_resource_with_callback(active_connection_id,
                                                  "analog-thermometer",
                                                  TEMPERATURE_SENSOR,
                                                  1,
                                                  MAX_MEASURED_VALUE,
                                                  /* resource name */ NULL,
                                                  LWM2M_OPAQUE,
                                                  OPERATION_WRITE,
                                                  temperature2,
                                                  strlen((char *) temperature2) + 1,
                                                  free,
                                                  dummy_resource_callback);
    CHECK_EQUAL(PT_STATUS_ITEM_EXISTS, status);
    mock().checkExpectations();
    free_devices_data(devices_data);
}

TEST(pt_device_2_with_connection, test_pt_device_add_resource_with_callback_invalid_operations)
{
    uint8_t *temperature = (uint8_t *) strdup("1000k");
    devices_test_data_t *devices_data = register_devices(false /* one fails */);

    mh_expect_mutexing(&api_mutex);
    pt_status_t status = pt_device_add_resource_with_callback(active_connection_id,
                                                  "analog-thermometer",
                                                  TEMPERATURE_SENSOR,
                                                  1,
                                                  MAX_MEASURED_VALUE,
                                                  /* resource name */ NULL,
                                                  LWM2M_OPAQUE,
                                                  OPERATION_WRITE | OPERATION_EXECUTE,
                                                  temperature,
                                                  strlen((char *) temperature) + 1,
                                                  free,
                                                  dummy_resource_callback);
    CHECK_EQUAL(PT_STATUS_INVALID_PARAMETERS, status);

    mock().checkExpectations();
    free_devices_data(devices_data);
}

TEST(pt_device_2_with_connection, test_pt_device_create_with_feature_flags)
{
    mh_expect_mutexing(&api_mutex);
    pt_status_t status = pt_device_create_with_feature_flags(active_connection_id, "test-device", 3600, NONE, PT_DEVICE_FEATURE_NONE, NULL);
    CHECK(PT_STATUS_SUCCESS == status);
    mock().checkExpectations();

    mh_expect_mutexing(&api_mutex);
    mh_expect_mutexing(&api_mutex);
    mh_expect_mutexing(&api_mutex);
    mh_expect_mutexing(&api_mutex);
    mh_expect_mutexing(&api_mutex);
    mh_expect_mutexing(&api_mutex);
    status = pt_device_create_with_feature_flags(active_connection_id, "test-device-with-renewal", 3600, NONE, PT_DEVICE_FEATURE_CERTIFICATE_RENEWAL, NULL);
    CHECK(PT_STATUS_SUCCESS == status);
    mock().checkExpectations();

    // Resources created on previous call, so second call should fail
    mh_expect_mutexing(&api_mutex);
    mh_expect_mutexing(&api_mutex);
    mh_expect_mutexing(&api_mutex);
    status = pt_device_init_certificate_renewal_resources(active_connection_id, "test-device-with-renewal");
    CHECK(PT_STATUS_INVALID_PARAMETERS == status);
}

TEST(pt_device_2_with_connection, test_pt_device_init_renewal_resources)
{
    mh_expect_mutexing(&api_mutex);
    pt_status_t status = pt_device_create_with_feature_flags(active_connection_id, "test-device", 3600, NONE, PT_DEVICE_FEATURE_NONE, NULL);
    CHECK(PT_STATUS_SUCCESS == status);
    mock().checkExpectations();

    mh_expect_mutexing(&api_mutex);
    mh_expect_mutexing(&api_mutex);
    status = pt_device_init_certificate_renewal_resources(active_connection_id, "test-device");
    CHECK(PT_STATUS_INVALID_PARAMETERS == status);
}
