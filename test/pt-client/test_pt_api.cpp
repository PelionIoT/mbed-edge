#include "CppUTest/TestHarness.h"
#include "CppUTestExt/MockSupport.h"
#include "jansson.h"
#include <string.h>
#include <assert.h>
#include <stdbool.h>
extern "C" {
#include "event2/bufferevent.h"
#include "event2/event.h"
#include "pt-client/pt_api.h"
#include "pt-client/client.h"
#include "pt-client/pt_api_internal.h"
#include "common/constants.h"
#include "common/websocket_comm.h"
#include "mbed-trace/mbed_trace.h"
#include <arpa/inet.h>
#include "edge-rpc/rpc.h"
#include "test-lib/evbase_mock.h"
#include "ns_list.h"
}

#define TRACE_GROUP "test_pt_api"
#define JSON_OK_RESPONSE "{\"id\": \"0\", \"jsonrpc\": \"2.0\", \"result\": \"ok\"}"
#define SAMPLE_USER_DATA "id1000"
#define TESTED_DEVICE_ID "tested_device_id"

static const char *device_id_string = "test device";
static void reset_jansson_allocator();

struct init_expectations_t {
    struct event_base *base;
    struct bufferevent *event;
};

static struct context* init_ctx();
static struct connection *init_connection(struct context *ctx);

static void expect_mutexing()
{
    mock().expectOneCall("edge_mutex_lock").withPointerParameter("mutex", (void *) &rpc_mutex).andReturnValue(0);
    mock().expectOneCall("edge_mutex_unlock").withPointerParameter("mutex", (void *) &rpc_mutex).andReturnValue(0);
}

static struct init_expectations_t *connection_init_expectations()
{
    struct init_expectations_t *init_expectations =
            (struct init_expectations_t *) calloc(1, sizeof(struct init_expectations_t));
    struct event_base *base = evbase_mock_new();
    struct bufferevent *event = (struct bufferevent *) calloc(1, sizeof(struct bufferevent));
    init_expectations->base = base;
    init_expectations->event = event;
    mock().expectOneCall("event_base_new")
            .andReturnValue(base);
    return init_expectations;
}

static void free_init_expectations(struct init_expectations_t *init_expectations)
{
    evbase_mock_delete(init_expectations->base);
    free(init_expectations->event);
    free(init_expectations);
}

static void free_context(struct context *ctx)
{
    mock().expectOneCall("event_base_free")
            .withPointerParameter("base", ctx->ev_base);
    event_base_free(ctx->ev_base);
    free(ctx);
}

struct connection_test_data {
    struct init_expectations_t *init_expectations;
    struct context *ctx;
    struct connection *connection;
};

static struct connection_test_data *start_connection_test()
{
    struct connection_test_data *data = (struct connection_test_data *) calloc(1, sizeof(struct connection_test_data));
    data->init_expectations = (struct init_expectations_t *) connection_init_expectations();
    data->ctx = init_ctx();
    data->connection = init_connection(data->ctx);
    return data;
}

static void destroy_connection(connection_t* connection)
{
    free(connection->client_data);

    // Not all tests use or init transport connection.
    if (connection->transport_connection) {
        free(((websocket_connection_t*) connection->transport_connection->transport)->sent);
        free(connection->transport_connection->transport);
        free(connection->transport_connection);
    }
    free(connection);
}

static void close_connection_test(struct connection_test_data *test_data)
{
    free_context(test_data->ctx);
    free_init_expectations(test_data->init_expectations);
    destroy_connection(test_data->connection);
    free(test_data);
}

static void test_resource_callback(const pt_resource_t *resource,
                                   const uint8_t *value,
                                   const uint32_t value_size,
                                   void *userdata)
{
    mock().actualCall("test_resource_callback")
            .withPointerParameter("resource", (void *) resource)
            .withPointerParameter("value", (void *) value)
            .withIntParameter("value_size", value_size)
            .withPointerParameter("userdata", userdata);
}

char* test_msg_generate_id()
{
    return strdup("1");
}

TEST_GROUP(pt_api) {
    void setup()
    {
        rpc_set_generate_msg_id(test_msg_generate_id);
    }

    void teardown()
    {
        expect_mutexing();
        rpc_destroy_messages();
        reset_jansson_allocator();
    }
};

static void* mock_malloc(size_t size)
{
    mock().actualCall("jansson_malloc");
    if (mock().boolReturnValue()) {
        return malloc(size);
    }
    return NULL;
}

static void mock_free(void *ptr)
{
    mock().actualCall("jansson_free");
    free(ptr);
}

static void setup_jansson_mock_allocator()
{
    json_set_alloc_funcs(mock_malloc, mock_free);
}

static void reset_jansson_allocator()
{
    json_set_alloc_funcs(malloc, free);
}

static void pt_register_success_handler(void* userdata)
{
    mock().actualCall("pt_register_success_handler")
            .withConstPointerParameter("userdata", userdata);
}

static void pt_register_failure_handler(void* userdata)
{
    mock().actualCall("pt_register_failure_handler")
            .withConstPointerParameter("userdata", userdata);
}

static void device_write_value_success(const char* device_id, void *userdata)
{
    mock().actualCall("device_write_value_success")
            .withStringParameter("device_id", device_id)
            .withPointerParameter("userdata", userdata);
}

static void device_write_value_failure(const char* device_id, void *userdata)
{
    mock().actualCall("device_write_value_failure")
            .withStringParameter("device_id", device_id)
            .withPointerParameter("userdata", userdata);
}

static void device_register_success(const char* device_id, void *userdata)
{
    mock().actualCall("device_register_success")
            .withStringParameter("device_id", device_id)
            .withPointerParameter("userdata", userdata);
}

static void device_register_failure(const char* device_id, void *userdata)
{
    mock().actualCall("device_register_failure")
            .withStringParameter("device_id", device_id)
            .withPointerParameter("userdata", userdata);
}

static void device_unregister_success(const char* device_id, void *userdata)
{
    mock().actualCall("device_unregister_success")
            .withStringParameter("device_id", device_id)
            .withPointerParameter("userdata", userdata);
}

static void device_unregister_failure(const char* device_id, void *userdata)
{
    mock().actualCall("device_unregister_failure")
            .withStringParameter("device_id", device_id)
            .withPointerParameter("userdata", userdata);
}


static void success_handler(void *userdata)
{
    mock().actualCall("success_handler")
            .withPointerParameter("userdata", userdata);
}

static void failure_handler(void *userdata)
{
    mock().actualCall("failure_handler")
            .withPointerParameter("userdata", userdata);
}

void protocol_translator_registration_dummy(void *userdata)
{
}

void connection_ready_handler_test(struct connection *connection, void *userdata)
{
    pt_register_protocol_translator(connection,
                                    protocol_translator_registration_dummy,
                                    protocol_translator_registration_dummy,
                                    NULL);
}

TEST(pt_api, test_register_close_connection_and_register_again)
{
    const char* userdata = "dummy_data";

    expect_mutexing();
    //Register
    struct context *ctx;
    struct init_expectations_t *init_expectations = (struct init_expectations_t *) connection_init_expectations();
    ctx = (struct context*)calloc(1, sizeof(struct context));
    ctx->json_flags = JSON_COMPACT;
    ctx->ev_base = event_base_new();

    struct connection *connection = init_connection(ctx);
    connection->connected = true;
    connection->client_data->registered = false;
    pt_status_t status = pt_register_protocol_translator(connection,
                                                         pt_register_success_handler,
                                                         pt_register_failure_handler,
                                                         (void*) userdata);
    CHECK_EQUAL(PT_STATUS_SUCCESS, status);

    //Unregister
    expect_mutexing();
    destroy_connection(connection);
    free_context(ctx);
    free_init_expectations(init_expectations);

    //Register again
    ctx = (struct context*)calloc(1, sizeof(struct context));
    init_expectations = (struct init_expectations_t *) connection_init_expectations();
    ctx->json_flags = JSON_COMPACT;
    ctx->ev_base = event_base_new();

    connection = init_connection(ctx);
    connection->connected = true;
    connection->client_data->registered = false;
    status = pt_register_protocol_translator(connection,
                                             pt_register_success_handler,
                                             pt_register_failure_handler,
                                             (void *) userdata);
    CHECK_EQUAL(PT_STATUS_SUCCESS, status);
    mock().checkExpectations();
    destroy_connection(connection);
    free_context(ctx);
    free_init_expectations(init_expectations);
}

int pt_client_write_dummy(connection_t *connection, char *data, size_t len)
{
    free(data);
    return 0;
}

static struct context* init_ctx()
{
    struct context *ctx;
    ctx = (struct context *) calloc(1, sizeof(struct context));
    ctx->json_flags = JSON_COMPACT;
    ctx->ev_base = event_base_new();
    return ctx;
}

static struct connection* init_connection(struct context * ctx)
{
    char *name = (char*) "jsonrpc";
    client_data_t *client_data = pt_client_create_protocol_translator(name);
    char *userdata = (char *) "dummy_userdata";

    protocol_translator_callbacks_t pt_cbs;
    pt_cbs.connection_ready_cb = connection_ready_handler_test;
    pt_cbs.received_write_cb = NULL;
    pt_cbs.connection_shutdown_cb = NULL;

    struct connection *connection = connection_init(ctx, client_data,
                                                    &pt_cbs, (void*) userdata);
    connection->client_data->registered = true;

    //Add transport connection
    websocket_connection_t *websocket_connection = (websocket_connection_t*) calloc(1, sizeof(websocket_connection_t));
    websocket_connection->sent = (websocket_message_list_t*) calloc(1, sizeof(websocket_message_list_t));

    ns_list_init(websocket_connection->sent);
    transport_connection_t *transport_connection = (transport_connection_t*) malloc(sizeof(transport_connection_t));

    transport_connection->write_function = pt_client_write_dummy;
    transport_connection->transport = websocket_connection;
    connection->transport_connection = transport_connection;

    return connection;
}

TEST(pt_api, test_pt_register_device)
{
    struct init_expectations_t *init_expectations = (struct init_expectations_t *) connection_init_expectations();
    struct context *ctx = init_ctx();
    struct connection *connection = init_connection(ctx);
    connection->connected = true;
    const char *my_data = "test_data";

    pt_status_t status = PT_STATUS_SUCCESS;
    const uint16_t opaque_id1 = 0;
    const uint16_t opaque_id2 = 2;
    const char *opaque_data_string ="Temp 100 F";
    const uint16_t object_id = 5432;
    const uint16_t object_instance_id = 0;

    char *device_id = strndup(device_id_string, strlen(device_id_string));
    pt_device_t *device = pt_create_device(device_id, 86400, QUEUE, &status);
    CHECK_EQUAL(PT_STATUS_SUCCESS, status);

    pt_object_t *object = pt_device_add_object(device, object_id, &status);
    CHECK_EQUAL(PT_STATUS_SUCCESS, status);
    pt_object_instance_t *instance = pt_object_add_object_instance(object, object_instance_id, &status);
    CHECK_EQUAL(PT_STATUS_SUCCESS, status);

    unsigned int operations = 0;
    operations |= (OPERATION_READ | OPERATION_WRITE);

    char *data = strndup(opaque_data_string, strlen(opaque_data_string));
    char *data2 = strndup(opaque_data_string, strlen(opaque_data_string));
    pt_object_instance_add_resource_with_callback(instance, opaque_id1, LWM2M_OPAQUE,
                                                  operations, (uint8_t*) data, strlen(data) + 1,
                                                  &status, test_resource_callback);
    CHECK_EQUAL(PT_STATUS_SUCCESS, status);
    pt_object_instance_add_resource_with_callback(instance, opaque_id2, LWM2M_OPAQUE,
                                                  operations, (uint8_t*) data2, strlen(data2) + 1,
                                                  &status, test_resource_callback);
    CHECK_EQUAL(PT_STATUS_SUCCESS, status);
    tr_info("Register device '%s'\n", device_id);
    expect_mutexing();
    pt_register_device(connection, device, device_register_success, device_register_failure, (void *) my_data);
    pt_device_free(device);
    mock().checkExpectations();
    free_context(ctx);
    destroy_connection(connection);
    free_init_expectations(init_expectations);
}

typedef struct my_user_data_s {
    char *data_str;
} my_user_data_t;

static void free_my_user_data(void *_data)
{
    my_user_data_t *data = (my_user_data_t *) _data;
    free(data->data_str);
    free(data);
}

TEST(pt_api, test_pt_unregister_device)
{
    const char *my_data = "test_data";
    struct init_expectations_t *init_expectations = (struct init_expectations_t *) connection_init_expectations();
    struct context *ctx = init_ctx();
    struct connection *connection = init_connection(ctx);
    my_user_data_t *data = (my_user_data_t *) calloc(1, sizeof(my_user_data_t));
    data->data_str = (char *) malloc(10);
    pt_device_userdata_t *userdata = pt_api_create_device_userdata(data, free_my_user_data);
    sprintf(data->data_str, "hello");
    connection->connected = true;
    pt_status_t status = PT_STATUS_SUCCESS;

    char *device_id = strndup(device_id_string, strlen(device_id_string));
    pt_device_t *device = pt_create_device_with_userdata(device_id, 86400, QUEUE, &status, userdata);
    CHECK_EQUAL(PT_STATUS_SUCCESS, status);

    tr_info("Unregister device '%s'\n", device_id);
    expect_mutexing();
    pt_unregister_device(connection, device, device_unregister_success, device_unregister_failure, (void *) my_data);
    pt_device_free(device);
    free_context(ctx);
    destroy_connection(connection);
    mock().checkExpectations();
    free_init_expectations(init_expectations);
}

static void write_value_test(struct connection_test_data *test_data)
{
    pt_status_t status = PT_STATUS_SUCCESS;
    const uint16_t opaque_id1 = 0;
    const uint16_t opaque_id2 = 2;
    const uint16_t object_id = 0;
    const uint16_t object_instance_id = 0;
    const char *opaque_data_string ="Temp 100 F";
    char *data = strndup(opaque_data_string, strlen(opaque_data_string));
    char *data2 = strndup(opaque_data_string, strlen(opaque_data_string));
    char *device_id = strndup(device_id_string, strlen(device_id_string));
    unsigned int operations = 0;
    /* Pass only valid set of operations */
    operations |= (OPERATION_READ | OPERATION_WRITE);

    pt_device_t *device = pt_create_device(device_id, 86400, QUEUE, &status);
    CHECK_EQUAL(PT_STATUS_SUCCESS, status);
    pt_object_t *object = pt_device_add_object(device, object_id, &status);
    CHECK_EQUAL(PT_STATUS_SUCCESS, status);
    pt_object_instance_t *instance = pt_object_add_object_instance(object, object_instance_id, &status);
    CHECK_EQUAL(PT_STATUS_SUCCESS, status);
    pt_object_instance_add_resource_with_callback(instance, opaque_id1, LWM2M_OPAQUE,
                                                  operations, (uint8_t*) data, strlen(data) + 1,
                                                  &status, test_resource_callback);
    CHECK_EQUAL(PT_STATUS_SUCCESS, status);
    pt_object_instance_add_resource_with_callback(instance, opaque_id2, LWM2M_OPAQUE,
                                                  operations, (uint8_t*) data2, strlen(data2) + 1,
                                                  &status, test_resource_callback);
    CHECK_EQUAL(PT_STATUS_SUCCESS, status);
    pt_status_t expected_return_value = PT_STATUS_SUCCESS;
    if (!test_data->connection->connected) {
        expected_return_value = PT_STATUS_NOT_CONNECTED;
        mock().expectOneCall("device_write_value_failure").withStringParameter("device_id", device_id).withPointerParameter("userdata", (void *) SAMPLE_USER_DATA);
    }
    int rc = pt_write_value(test_data->connection,
                   device,
                   device->objects,
                   device_write_value_success,
                   device_write_value_failure,
                   (void *) SAMPLE_USER_DATA);
    CHECK_EQUAL(expected_return_value, rc);
    pt_device_free(device);
}

TEST(pt_api, test_pt_write_value_write_succeeds)
{
    struct connection_test_data *test_data = start_connection_test();
    test_data->connection->connected = true;
    expect_mutexing();
    write_value_test(test_data);
    close_connection_test(test_data);
    mock().checkExpectations();
}

TEST(pt_api, test_pt_write_value_write_fails)
{
    struct connection_test_data *test_data = start_connection_test();
    write_value_test(test_data);
    close_connection_test(test_data);
    mock().checkExpectations();
}

TEST(pt_api, test_pt_write_value_not_connected)
{
    struct connection_test_data *test_data = start_connection_test();
    write_value_test(test_data);
    close_connection_test(test_data);
    mock().checkExpectations();
}

TEST(pt_api, test_id_reserved_on_device_structure)
{
    char* device_id = strndup("test-device", strlen("test-device"));
    const uint16_t id = 0;
    const uint16_t id2 = 1;
    pt_status_t status = PT_STATUS_SUCCESS;

    pt_device_t *device = pt_create_device(device_id, 86400, QUEUE, &status);
    pt_object_t *object = pt_device_add_object(device, id, &status);
    CHECK_EQUAL(PT_STATUS_SUCCESS, status);
    CHECK(object != NULL);

    // Second object
    object = pt_device_add_object(device, id2, &status);
    CHECK_EQUAL(PT_STATUS_SUCCESS, status);
    CHECK(object != NULL);

    // Existing object
    CHECK(pt_device_add_object(device, id, &status) == NULL);
    CHECK_EQUAL(PT_STATUS_ITEM_EXISTS, status);

    pt_object_t *found_object = pt_device_find_object(device, id);
    CHECK(found_object != NULL);
    CHECK_EQUAL(0, found_object->id);

    status = PT_STATUS_SUCCESS;
    pt_object_instance_t *instance = pt_object_add_object_instance(object, id, &status);
    CHECK_EQUAL(PT_STATUS_SUCCESS, status);
    CHECK(instance != NULL);

    // Second instance
    instance = pt_object_add_object_instance(object, id2, &status);
    CHECK_EQUAL(PT_STATUS_SUCCESS, status);
    CHECK(instance != NULL);

    pt_object_instance_t *found_instance = pt_object_find_object_instance(object, id);
    CHECK(found_instance != NULL);
    CHECK_EQUAL(0, found_instance->id);

    // Existing instance
    CHECK(pt_object_add_object_instance(object, id, &status) == NULL);
    CHECK_EQUAL(PT_STATUS_ITEM_EXISTS, status);

    status = PT_STATUS_SUCCESS;
    pt_resource_t *resource =
        pt_object_instance_add_resource_with_callback(instance, id, LWM2M_OPAQUE,
                                                      0, NULL, 0, &status,
                                                      test_resource_callback);
    CHECK_EQUAL(PT_STATUS_SUCCESS, status);
    CHECK(resource != NULL);

    // Second resource
    resource = pt_object_instance_add_resource_with_callback(instance, id2, LWM2M_OPAQUE,
                                                             0, NULL, 0, &status,
                                                             test_resource_callback);
    CHECK_EQUAL(PT_STATUS_SUCCESS, status);
    CHECK(resource != NULL);

    // Existing resource
    pt_resource_t *found_resource = pt_object_instance_find_resource(instance, id);
    CHECK(found_resource != NULL);
    CHECK_EQUAL(0, found_resource->id);

    CHECK(pt_object_instance_add_resource_with_callback(instance, id, LWM2M_OPAQUE,
                                                        0, NULL, 0, &status,
                                                        test_resource_callback) == NULL);
    CHECK_EQUAL(PT_STATUS_ITEM_EXISTS, status);

    pt_device_free(device);
    mock().checkExpectations();
}

TEST(pt_api, test_register_protocol_translator_invalid_parameters)
{
    // protocol translator not registered
    struct init_expectations_t *init_expectations = (struct init_expectations_t *) connection_init_expectations();
    struct context *ctx = init_ctx();
    struct connection *connection = init_connection(ctx);

    /* Free the existing name and set it to null */
    connection->client_data->name = NULL;
    CHECK_EQUAL(pt_register_protocol_translator(connection, success_handler, failure_handler, NULL), PT_STATUS_ERROR);

    /* Create a new name for testing already registered protocol translator */
    connection->client_data->name = strdup("Test-name");
    connection->client_data->registered = 1;
    CHECK_EQUAL(pt_register_protocol_translator(connection, success_handler, failure_handler, NULL), PT_STATUS_ERROR);

    setup_jansson_mock_allocator();
    mock().expectNCalls(5, "jansson_malloc").andReturnValue(false);
    connection->client_data->registered = 0;
    CHECK_EQUAL(pt_register_protocol_translator(connection, success_handler, failure_handler, NULL), PT_STATUS_ALLOCATION_FAIL);
    pt_client_protocol_translator_destroy(&connection->client_data);
    free_context(ctx);
    free_init_expectations(init_expectations);
    destroy_connection(connection);
    mock().checkExpectations();
}

TEST(pt_api, test_pt_handle_pt_register_success)
{
    json_error_t error;
    const char *sample_user_data = SAMPLE_USER_DATA;
    struct pt_customer_callback customer_callback = { 0 };
    customer_callback.success_handler = pt_register_success_handler;
    customer_callback.failure_handler = pt_register_failure_handler;
    customer_callback.userdata = (void *) sample_user_data;

    json_t *response = json_loads(JSON_OK_RESPONSE, 0, &error);

    struct connection_test_data *test_data = start_connection_test();
    customer_callback.connection = test_data->connection;

    mock().expectOneCall("pt_register_success_handler")
                .withConstPointerParameter("userdata", sample_user_data);
    pt_handle_pt_register_success(response, (void *) &customer_callback);
    json_decref(response);
    close_connection_test(test_data);
    mock().checkExpectations();
}

TEST(pt_api, test_pt_handle_pt_register_failure)
{
    json_error_t error;
    const char *sample_user_data = SAMPLE_USER_DATA;
    struct pt_customer_callback customer_callback = { 0 };
    customer_callback.success_handler = pt_register_success_handler;
    customer_callback.failure_handler = pt_register_failure_handler;
    customer_callback.userdata = (void *) sample_user_data;
    json_t *response = json_loads(JSON_OK_RESPONSE, 0, &error);

    struct connection_test_data *test_data = start_connection_test();
    customer_callback.connection = test_data->connection;

    mock().expectOneCall("pt_register_failure_handler")
                .withConstPointerParameter("userdata", sample_user_data);
    pt_handle_pt_register_failure(response, (void *) &customer_callback);
    json_decref(response);
    close_connection_test(test_data);
    mock().checkExpectations();
}

TEST(pt_api, test_pt_handle_device_registration_success)
{
    json_error_t error;
    const char *sample_user_data = SAMPLE_USER_DATA;
    struct pt_device_customer_callback customer_callback = { 0 };
    customer_callback.success_handler = device_register_success;
    customer_callback.failure_handler = device_register_failure;
    customer_callback.userdata = (void *) sample_user_data;
    customer_callback.device_id = (char *) TESTED_DEVICE_ID;

    json_t *response = json_loads(JSON_OK_RESPONSE, 0, &error);

    struct connection_test_data *test_data = start_connection_test();

    mock().expectOneCall("device_register_success")
            .withPointerParameter("userdata", (void *) sample_user_data)
            .withStringParameter("device_id", (char *) TESTED_DEVICE_ID);
    pt_handle_device_register_success(response, (void *) &customer_callback);
    json_decref(response);
    close_connection_test(test_data);
    mock().checkExpectations();
}

TEST(pt_api, test_pt_handle_device_registration_failure)
{
    json_error_t error;
    const char *sample_user_data = SAMPLE_USER_DATA;
    struct pt_device_customer_callback customer_callback = { 0 };
    customer_callback.success_handler = device_register_success;
    customer_callback.failure_handler = device_register_failure;
    customer_callback.userdata = (void *) sample_user_data;
    customer_callback.device_id = (char *) TESTED_DEVICE_ID;

    json_t *response = json_loads(JSON_OK_RESPONSE, 0, &error);

    struct connection_test_data *test_data = start_connection_test();

    mock().expectOneCall("device_register_failure")
            .withPointerParameter("userdata", (void *) sample_user_data)
            .withStringParameter("device_id", (char *) TESTED_DEVICE_ID);
    pt_handle_device_register_failure(response, (void *) &customer_callback);
    json_decref(response);
    close_connection_test(test_data);
    mock().checkExpectations();
}

TEST(pt_api, test_pt_handle_device_unregistration_success)
{
    json_error_t error;
    const char *sample_user_data = SAMPLE_USER_DATA;
    struct pt_device_customer_callback customer_callback = { 0 };
    customer_callback.success_handler = device_unregister_success;
    customer_callback.failure_handler = device_unregister_failure;
    customer_callback.userdata = (void *) sample_user_data;
    customer_callback.device_id = (char *) TESTED_DEVICE_ID;
    json_t *response = json_loads(JSON_OK_RESPONSE, 0, &error);

    struct connection_test_data *test_data = start_connection_test();

    mock().expectOneCall("device_unregister_success")
            .withPointerParameter("userdata", (void *) sample_user_data)
            .withStringParameter("device_id", (char *) TESTED_DEVICE_ID);
    pt_handle_device_unregister_success(response, (void *) &customer_callback);
    json_decref(response);
    close_connection_test(test_data);
    mock().checkExpectations();
}

TEST(pt_api, test_pt_handle_device_unregistration_failure)
{
    json_error_t error;
    const char *sample_user_data = SAMPLE_USER_DATA;
    struct pt_device_customer_callback customer_callback = { 0 };
    customer_callback.success_handler = device_unregister_success;
    customer_callback.failure_handler = device_unregister_failure;
    customer_callback.userdata = (void *) sample_user_data;
    customer_callback.device_id = (char *) TESTED_DEVICE_ID;
    json_t *response = json_loads(JSON_OK_RESPONSE, 0, &error);

    struct connection_test_data *test_data = start_connection_test();

    mock().expectOneCall("device_unregister_failure")
            .withPointerParameter("userdata", (void *) sample_user_data)
            .withStringParameter("device_id", (char *) TESTED_DEVICE_ID);
    pt_handle_device_unregister_failure(response, (void *) &customer_callback);
    json_decref(response);
    close_connection_test(test_data);
    mock().checkExpectations();
}

TEST(pt_api, test_pt_handle_write_value_success)
{
    json_error_t error;
    const char *sample_user_data = SAMPLE_USER_DATA;
    struct pt_device_customer_callback customer_callback = { 0 };
    customer_callback.success_handler = device_write_value_success;
    customer_callback.failure_handler = device_write_value_failure;
    customer_callback.userdata = (void *) sample_user_data;
    customer_callback.device_id = (char *) TESTED_DEVICE_ID;

    json_t *response = json_loads(JSON_OK_RESPONSE, 0, &error);

    struct connection_test_data *test_data = start_connection_test();

    mock().expectOneCall("device_write_value_success")
            .withPointerParameter("userdata", (void *) sample_user_data)
            .withStringParameter("device_id", (char *) TESTED_DEVICE_ID);
    pt_handle_pt_write_value_success(response, (void *) &customer_callback);
    json_decref(response);
    close_connection_test(test_data);
    mock().checkExpectations();
}

TEST(pt_api, test_pt_handle_write_value_failure)
{
    json_error_t error;
    const char *sample_user_data = SAMPLE_USER_DATA;
    struct pt_device_customer_callback customer_callback = { 0 };
    customer_callback.success_handler = device_write_value_success;
    customer_callback.failure_handler = device_write_value_failure;
    customer_callback.userdata = (void *) sample_user_data;
    customer_callback.device_id = (char *) TESTED_DEVICE_ID;

    json_t *response = json_loads(JSON_OK_RESPONSE, 0, &error);
    struct connection_test_data *test_data = start_connection_test();
    mock().expectOneCall("device_write_value_failure")
            .withPointerParameter("userdata", (void *) sample_user_data)
            .withStringParameter("device_id", (char *) TESTED_DEVICE_ID);
    pt_handle_pt_write_value_failure(response, (void *) &customer_callback);
    json_decref(response);
    close_connection_test(test_data);
    mock().checkExpectations();
}

TEST(pt_api, test_device_registration_preconditions_no_connection)
{
    pt_device_t device = { 0 };
    CHECK(PT_STATUS_ERROR ==
          check_device_registration_preconditions(NULL, &device, "unregister", "cannot unregister a device."));
    mock().checkExpectations();
}

TEST(pt_api, test_device_registration_preconditions_no_device)
{
    struct connection_test_data *test_data = start_connection_test();
    CHECK(PT_STATUS_INVALID_PARAMETERS ==
          check_device_registration_preconditions(test_data->connection, NULL, "register", "register before devices."));
    close_connection_test(test_data);
    mock().checkExpectations();
}

TEST(pt_api, test_device_registration_preconditions_pt_not_registered)
{
    pt_device_t device = { 0 };
    struct connection_test_data *test_data = start_connection_test();
    test_data->connection->client_data->registered = false;
    CHECK(PT_STATUS_ERROR == check_device_registration_preconditions(test_data->connection, &device, "register", "register before devices."));
    close_connection_test(test_data);
    mock().checkExpectations();
}

TEST(pt_api, test_registration_data_allocated_fails)
{
    json_t *register_msg = allocate_base_request("device_register");
    json_t *params = json_object_get(register_msg, "params");
    json_t *j_objects = json_array();
    json_t *device_lifetime = json_integer(60);
    json_t *device_queuemode = NULL;
    json_t *device_id = json_string(TESTED_DEVICE_ID);
    struct connection_test_data *test_data = start_connection_test();

    struct pt_device_customer_callback *customer_callback = allocate_device_customer_callback(test_data->connection,
            device_register_success, device_register_failure, TESTED_DEVICE_ID, (void *) SAMPLE_USER_DATA);

    CHECK(PT_STATUS_ALLOCATION_FAIL == check_registration_data_allocated(
            register_msg, params, j_objects, device_lifetime, device_queuemode, device_id, customer_callback));
    close_connection_test(test_data);
    mock().checkExpectations();
}

TEST(pt_api, test_unregistration_data_allocated_fails)
{
    json_t *unregister_msg = NULL;
    json_t *params = json_object_get(unregister_msg, "params");
    json_t *device_id = json_string(TESTED_DEVICE_ID);

    struct connection_test_data *test_data = start_connection_test();

    struct pt_device_customer_callback *customer_callback = allocate_device_customer_callback(test_data->connection,
            device_unregister_success, device_unregister_failure, TESTED_DEVICE_ID, (void *) SAMPLE_USER_DATA);

    CHECK(PT_STATUS_ALLOCATION_FAIL ==
          check_unregistration_data_allocated(unregister_msg, params, device_id, customer_callback));
    close_connection_test(test_data);
    mock().checkExpectations();
}

TEST(pt_api, test_write_value_data_allocated_fails)
{
    json_t *request = allocate_base_request("write");
    json_t *params = json_object_get(request, "params");
    json_t *j_objects = NULL;
    json_t *device_id = json_string(TESTED_DEVICE_ID);

    struct connection_test_data *test_data = start_connection_test();

    struct pt_device_customer_callback *customer_callback = allocate_device_customer_callback(test_data->connection,
            device_write_value_success, device_write_value_failure, TESTED_DEVICE_ID, (void *) SAMPLE_USER_DATA);
    CHECK(PT_STATUS_ALLOCATION_FAIL ==
          check_write_value_data_allocated(request, params, j_objects, device_id, customer_callback));
    close_connection_test(test_data);
    mock().checkExpectations();
}

TEST(pt_api, test_write_data_frame_fails_no_message)
{
    struct connection_test_data *test_data = start_connection_test();
    test_data->connection->connected = true;
    struct pt_device_customer_callback *customer_callback = allocate_device_customer_callback(test_data->connection,
            device_write_value_success, device_write_value_failure, TESTED_DEVICE_ID, (void *) SAMPLE_USER_DATA);
    pt_status_t status = write_data_frame(NULL,
                                          pt_handle_pt_register_success,
                                          pt_handle_pt_register_failure,
                                          device_customer_callback_free_func,
                                          customer_callback);
    CHECK_EQUAL(PT_STATUS_ALLOCATION_FAIL, status);
    close_connection_test(test_data);
    mock().checkExpectations();
}

TEST(pt_api, test_add_object_to_device_no_device)
{
    pt_status_t status = PT_STATUS_SUCCESS;
    pt_device_add_object(NULL, 100, &status);
    CHECK(PT_STATUS_INVALID_PARAMETERS == status);
    mock().checkExpectations();
}

TEST(pt_api, test_find_object_no_device)
{
    CHECK(NULL == pt_device_find_object(NULL, 100));
    mock().checkExpectations();
}

TEST(pt_api, test_add_instance_no_object)
{
    pt_status_t status = PT_STATUS_SUCCESS;
    CHECK(NULL == pt_object_add_object_instance(NULL, 10, &status));
    CHECK_EQUAL(PT_STATUS_INVALID_PARAMETERS, status);
    mock().checkExpectations();
}

TEST(pt_api, test_find_object_instance_no_object)
{
    CHECK(NULL == pt_object_find_object_instance(NULL, 100));
    mock().checkExpectations();
}

TEST(pt_api, test_add_resource_no_instance)
{
    pt_status_t status = PT_STATUS_SUCCESS;

    CHECK(NULL == pt_object_instance_add_resource(NULL, 100, LWM2M_OPAQUE,
                                                  NULL, 0, &status));
    CHECK_EQUAL(PT_STATUS_INVALID_PARAMETERS, status);
    mock().checkExpectations();
}

TEST(pt_api, test_add_resource_callback_for_write)
{
    pt_status_t status = PT_STATUS_SUCCESS;
    pt_object_instance_t *instance = (pt_object_instance_t*) calloc(1, sizeof(pt_object_instance_t));
    pt_resource_list_t *resources = (pt_resource_list_t *) calloc(1, sizeof(pt_resource_list_t));
    ns_list_init(resources);
    instance->resources = resources;

    pt_resource_t *resource =
        pt_object_instance_add_resource_with_callback(instance, 100,
                                                      LWM2M_OPAQUE, OPERATION_WRITE,
                                                      NULL, 0, &status,
                                                      test_resource_callback);
    CHECK_EQUAL(PT_STATUS_SUCCESS, status);

    uint32_t value = 0;
    mock().expectOneCall("test_resource_callback")
        .withPointerParameter("resource", (void*) resource)
        .withPointerParameter("value", &value)
        .withIntParameter("value_size", 0)
        .withPointerParameter("userdata", NULL);
    /*
     * Check manually that the set callbacks are callable.
     * The current responsibility to call the callbacks are in the
     * customer implementation of `received_write_callback`
     */
    resource->callback(resource, (uint8_t*) &value, 0, NULL);

    mock().checkExpectations();
    free(instance);
    free(resources);
    free(resource);
}

TEST(pt_api, test_add_writable_resource_no_callback)
{
    pt_status_t status = PT_STATUS_SUCCESS;
    pt_object_instance_t *instance =
        (pt_object_instance_t*) calloc(1, sizeof(pt_object_instance_t));

    CHECK(NULL == pt_object_instance_add_resource_with_callback(instance, 100,
                                                                LWM2M_OPAQUE, OPERATION_WRITE,
                                                                NULL, 0, &status, NULL));
    CHECK_EQUAL(PT_STATUS_INVALID_PARAMETERS, status);
    free(instance);
    mock().checkExpectations();
}

TEST(pt_api, test_add_executable_resource_no_callback)
{
    pt_status_t status = PT_STATUS_SUCCESS;
    pt_object_instance_t *instance = (pt_object_instance_t*) calloc(1, sizeof(pt_object_instance_t));
    CHECK(NULL == pt_object_instance_add_resource_with_callback(instance, 100,
                                                                LWM2M_OPAQUE, OPERATION_EXECUTE,
                                                                NULL, 0, &status, NULL));
    CHECK_EQUAL(PT_STATUS_INVALID_PARAMETERS, status);
    free(instance);
    mock().checkExpectations();
}

TEST(pt_api, test_add_write_and_executable_resource)
{
    pt_status_t status = PT_STATUS_SUCCESS;
    pt_object_instance_t *instance = (pt_object_instance_t*) calloc(1, sizeof(pt_object_instance_t));
    CHECK(NULL ==
          pt_object_instance_add_resource_with_callback(instance, 100,
                                                        LWM2M_OPAQUE,
                                                        OPERATION_WRITE | OPERATION_EXECUTE,
                                                        NULL, 0, &status,
                                                        test_resource_callback));
    CHECK_EQUAL(PT_STATUS_INVALID_PARAMETERS, status);
    free(instance);
    mock().checkExpectations();
}

TEST(pt_api, test_write_value_with_no_device)
{
    struct connection_test_data *test_data = start_connection_test();
    CHECK(PT_STATUS_INVALID_PARAMETERS ==
          pt_write_value(test_data->connection,
                  NULL, NULL, device_write_value_success, device_write_value_failure, (void *) SAMPLE_USER_DATA));
    close_connection_test(test_data);
    mock().checkExpectations();
}
