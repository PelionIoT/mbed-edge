#include <string.h>
#include <stdio.h>
#include <inttypes.h>

#include "CppUTest/TestHarness.h"
#include "CppUTestExt/MockSupport.h"

#include "jansson.h"

#include <event2/bufferevent.h>
#include <event2/event.h>
#include "test-lib/msg_api_test_helper.h"
extern "C" {
#include "common/constants.h"
#include "common/websocket_comm.h"
#include "edge-core/server.h"
#include "edge-core/edge_server.h"
#include "edge-core/protocol_api.h"
#include "edge-core/protocol_crypto_api.h"
#include "edge-core/protocol_crypto_api_internal.h"
#include "edge-core/srv_comm.h"
#include "edge-client/edge_client.h"
#include "edge-client/edge_client_format_values.h"
#include "edge-rpc/rpc.h"
#include "ns_list.h"
#include "common/apr_base64.h"
#include "test-lib/evbase_mock.h"
#include "edge-core/websocket_serv.h"
#include "test-lib/server_test.h"
#include "libwebsocket-mock/lws_mock.h"
#include "test-lib/json_helper.h"
#include "common/pt_api_error_parser.h"
#include "certificate-enrollment-client/ce_status.h"
#include "certificate-enrollment-client/ce_defs.h"
#include "key_config_manager.h"
}
#include "event-os-mock/eventOS_event_mock.h"
#include "cpputest-custom-types/my_json_frame.h"
#include "cpputest-custom-types/value_pointer.h"
#include "test-lib/rpc_mocks.h"
#include "test-lib/test_edge_server.h"
#include "MbedCloudClient.h"


#define TEST_DEVICE_REGISTER_JSON   TEST_DATA_DIR "/device_register_test.json"
#define TEST_DEVICE_REGISTER_INVALID_OBJECT_JSON TEST_DATA_DIR "/device_register_test_object_missing.json"
#define TEST_DEVICE_REGISTER_INVALID_INSTANCE_JSON TEST_DATA_DIR "/device_register_test_instance_missing.json"
#define TEST_DEVICE_REGISTER_INVALID_RESOURCE_JSON TEST_DATA_DIR "/device_register_test_resource_missing.json"
#define TEST_DEVICE_REGISTER_INVALID_RESOURCE_VALUE_JSON                                                               \
    TEST_DATA_DIR "/device_register_test_invalid_resource_value.json"
#define TEST_DEVICE2_REGISTER_JSON  TEST_DATA_DIR "/device2_register_test.json"
#define TEST_DEVICE_UNREGISTER_JSON   TEST_DATA_DIR "/device_unregister_test.json"
#define TEST_DEVICE2_UNREGISTER_JSON  TEST_DATA_DIR "/device2_unregister_test.json"
#define TEST_COMPLEX_HIERARCHY_JSON  TEST_DATA_DIR "/complex_resource_hierarchy.json"
#define TEST_WRITE_VALUE_FAILURE_JSON TEST_DATA_DIR "/device_write_value_failure.json"
#define TEST_WRITE_NON_STRING_VALUE_JSON TEST_DATA_DIR "/device_write_non_string_value.json"
#define TEST_UNIX_SOCKET_PATH "TEST_UNIX_SOCKET_PATH"
#define TEST_LOCK_FILE_DESCRIPTOR_ID 20202
static void check_connection_free_expectations(struct connection *connection,
                                               int expected_object_id,
                                               int expected_object_instance_id,
                                               uint32_t registered_endpoints);
static void check_context(struct context *context,
                          int32_t expected_registered,
                          int32_t expected_not_accepted,
                          int32_t registered_endpoints);
static struct test_context *connection_initialized();
static struct test_context *protocol_translator_registered(int id);
static struct test_context *protocol_translator_not_registered();
static void free_test_context(struct test_context *test_context,
                              int32_t expected_registered,
                              int32_t expected_not_accepted,
                              int32_t registered_endpoints);
static void free_transport_connection(struct transport_connection *transport_connection);
static struct json_message_t* create_endpoint(struct connection *connection, const char *endpoint_json_filepath);
static void check_remove_resources_and_objects_owned_by_client(struct connection *connection, uint32_t total_endpoints);
static struct test_context *create_test_context(struct context *context);
static struct json_message_t *create_endpoint_with_expectations(struct connection *connection,
                                                                const char *endpoint_json_filepath,
                                                                int expected_rc,
                                                                const char *expected_json_string);

struct pt_device_count_expectations {
    char *get_resource_value;
    uint32_t *get_value_size;
    int16_t *set_resource_value;
    uint32_t *set_value_size;
};

struct test_context {
    struct context *context;
    struct connection *connection;
};

typedef struct value_pointer_entry {
    ValuePointer* value_pointer;
    ns_list_link_t link;
} value_pointer_entry_t;

static NS_LIST_DEFINE(_value_pointers, value_pointer_entry_t, link);

typedef struct {
    char **pt_device_amount_read;
    int16_t **pt_device_amount_set;
    ValuePointer** value_pointers;
    int32_t num_devices;
} multiple_devices_test_data_t;

static void alloc_multiple_devices_test_data(multiple_devices_test_data_t *data, int32_t num_devices);
static void free_multiple_devices_test_data(multiple_devices_test_data_t *data);

static void expect_mutexing()
{
    mock().expectOneCall("edge_mutex_lock").withPointerParameter("mutex", (void *) &rpc_mutex).andReturnValue(0);
    mock().expectOneCall("edge_mutex_unlock").withPointerParameter("mutex", (void *) &rpc_mutex).andReturnValue(0);
}

/**
 * \brief Create structure holding the expectations counts for device creation.
 *        This function changes the byte order of input parameter to network short.
 *        The Edge client API expects to get data in network byte-order and the
 *        protocol translator changes the order.
 * \param get_resource_value The current value as string in the Mbed Device Management Client resource.
 * \param set_resource_value The value to write to Mbed Device Management Client in host byte order.
 */
static struct pt_device_count_expectations *pt_create_device_count_expectations(const char *get_resource_value,
                                                                                int16_t set_resource_value)
{
    struct pt_device_count_expectations *dce = (struct pt_device_count_expectations *) malloc(
            sizeof(struct pt_device_count_expectations));
    dce->get_resource_value = strdup(get_resource_value);
    dce->get_value_size = (uint32_t*) malloc(sizeof(uint32_t));
    *dce->get_value_size = strlen(get_resource_value);

    dce->set_resource_value = (int16_t*) malloc(sizeof(uint16_t));
    *dce->set_resource_value = htons(set_resource_value);
    dce->set_value_size = (uint32_t*) malloc(sizeof(uint32_t));
    *dce->set_value_size = sizeof(int16_t);

    return dce;
}

static void free_pt_device_count_expectations(struct pt_device_count_expectations* dce)
{
    free(dce->get_value_size);
    free(dce->set_resource_value);
    free(dce->set_value_size);
    free(dce);
}

static char* test_msg_generate_id()
{
    return strndup("1", strlen("1"));
}

static void free_value_pointers()
{
    ns_list_foreach_safe(value_pointer_entry_t, cur, &_value_pointers) {
        ns_list_remove(&_value_pointers, cur);
        delete cur->value_pointer;
        free(cur);
    }
}

static void expected_device_register_test_structure(void* connection)
{
    ValuePointer *null_value_pointer = new ValuePointer(NULL, 0);
    ValuePointer *string_value_pointer = new ValuePointer((uint8_t*) "test_string", strlen("test_string"));
    ValuePointer *int_value_pointer = new ValuePointer((uint8_t*) "100", strlen("100"));
    ValuePointer *float_value_pointer = new ValuePointer((uint8_t*) "0.1", strlen("0.1"));
    ValuePointer *bool_value_pointer = new ValuePointer((uint8_t*) "true", strlen("true"));
    ValuePointer *opq1_value_pointer = new ValuePointer((uint8_t*) "opaque 1", strlen("opaque 1"));
    ValuePointer *time_value_pointer = new ValuePointer((uint8_t*) "1505114436", strlen("1505114436"));
    ValuePointer *opq2_value_pointer = new ValuePointer((uint8_t*) "opaque 2", strlen("opaque 2"));
    ValuePointer *opq4_value_pointer = new ValuePointer((uint8_t*) "opaque 4", strlen("opaque 4"));
    ValuePointer *opq3_value_pointer = new ValuePointer((uint8_t*) "opaque 3", strlen("opaque 3"));

    mock().expectOneCall("edgeclient_verify_value")
            .withParameterOfType("ValuePointer", "value", (const void *) null_value_pointer)
            .withParameter("value_length", 0)
            .withParameter("resource_type", LWM2M_OPAQUE)
            .andReturnValue(true);

    mock().expectOneCall("edgeclient_verify_value")
            .withParameterOfType("ValuePointer", "value", (const void *) null_value_pointer)
            .withParameter("value_length", 0)
            .withParameter("resource_type", LWM2M_OPAQUE)
            .andReturnValue(true);

    mock().expectOneCall("edgeclient_verify_value")
            .withParameterOfType("ValuePointer", "value", (const void *) null_value_pointer)
            .withParameter("value_length", 0)
            .withParameter("resource_type", LWM2M_OPAQUE)
            .andReturnValue(true);

    mock().expectOneCall("edgeclient_verify_value")
            .withParameterOfType("ValuePointer", "value", (const void *) null_value_pointer)
            .withParameter("value_length", 0)
            .withParameter("resource_type", LWM2M_OPAQUE)
            .andReturnValue(true);

    mock().expectOneCall("edgeclient_verify_value")
            .withParameterOfType("ValuePointer", "value", (const void *) string_value_pointer)
            .withParameter("value_length", strlen("test_string"))
            .withParameter("resource_type", LWM2M_STRING)
            .andReturnValue(true);

    mock().expectOneCall("edgeclient_verify_value")
            .withParameterOfType("ValuePointer", "value", (const void *) int_value_pointer)
            .withParameter("value_length", strlen("100"))
            .withParameter("resource_type", LWM2M_INTEGER)
            .andReturnValue(true);

    mock().expectOneCall("edgeclient_verify_value")
            .withParameterOfType("ValuePointer", "value", (const void *) float_value_pointer)
            .withParameter("value_length", strlen("0.1"))
            .withParameter("resource_type", LWM2M_FLOAT)
            .andReturnValue(true);

    mock().expectOneCall("edgeclient_verify_value")
            .withParameterOfType("ValuePointer", "value", (const void *) bool_value_pointer)
            .withParameter("value_length", strlen("true"))
            .withParameter("resource_type", LWM2M_BOOLEAN)
            .andReturnValue(true);

    mock().expectOneCall("edgeclient_verify_value")
            .withParameterOfType("ValuePointer", "value", (const void *) opq1_value_pointer)
            .withParameter("value_length", strlen("opaque 1"))
            .withParameter("resource_type", LWM2M_OPAQUE)
            .andReturnValue(true);

    mock().expectOneCall("edgeclient_verify_value")
            .withParameterOfType("ValuePointer", "value", (const void *) time_value_pointer)
            .withParameter("value_length", strlen("1505114436"))
            .withParameter("resource_type",LWM2M_TIME)
            .andReturnValue(true);

    mock().expectOneCall("edgeclient_verify_value")
            .withParameterOfType("ValuePointer", "value", (const void *) opq2_value_pointer)
            .withParameter("value_length", strlen("opaque 2"))
            .withParameter("resource_type", LWM2M_OPAQUE)
            .andReturnValue(true);

    mock().expectOneCall("edgeclient_verify_value")
            .withParameterOfType("ValuePointer", "value", (const void *) opq3_value_pointer)
            .withParameter("value_length", strlen("opaque 3"))
            .withParameter("resource_type", LWM2M_OPAQUE)
            .andReturnValue(true);

    mock().expectOneCall("edgeclient_verify_value")
            .withParameterOfType("ValuePointer", "value", (const void *) opq4_value_pointer)
            .withParameter("value_length", strlen("opaque 4"))
            .withParameter("resource_type", LWM2M_OPAQUE)
            .andReturnValue(true);

    mock().expectOneCall("set_resource_value")
            .withStringParameter("endpoint_name", "test-device")
            .withParameter("object_id", 10)
            .withParameter("object_instance_id", 0)
            .withParameter("resource_id", 1)
            .withParameterOfType("ValuePointer", "value", (const void *) null_value_pointer)
            .withParameter("value_length", 0)
            .withParameter("resource_type", LWM2M_OPAQUE)
            .withParameter("opr", OPERATION_READ)
            .withPointerParameter("ctx", connection)
            .andReturnValue(PT_API_SUCCESS);

    mock().expectOneCall("set_resource_value")
            .withStringParameter("endpoint_name", "test-device")
            .withParameter("object_id", 10)
            .withParameter("object_instance_id", 0)
            .withParameter("resource_id", 2)
            .withParameterOfType("ValuePointer", "value", (const void *) null_value_pointer)
            .withParameter("value_length", 0)
            .withParameter("resource_type", LWM2M_OPAQUE)
            .withParameter("opr", OPERATION_READ_WRITE)
            .withPointerParameter("ctx", connection)
            .andReturnValue(PT_API_SUCCESS);

    mock().expectOneCall("set_resource_value")
            .withStringParameter("endpoint_name", "test-device")
            .withParameter("object_id", 10)
            .withParameter("object_instance_id", 5)
            .withParameter("resource_id", 0)
            .withParameterOfType("ValuePointer", "value", (const void *) null_value_pointer)
            .withParameter("value_length", 0)
            .withParameter("resource_type", LWM2M_OPAQUE)
            .withParameter("opr", OPERATION_READ)
            .withPointerParameter("ctx", connection)
            .andReturnValue(PT_API_SUCCESS);

    mock().expectOneCall("set_resource_value")
            .withStringParameter("endpoint_name", "test-device")
            .withParameter("object_id", 13)
            .withParameter("object_instance_id", 0)
            .withParameter("resource_id", 37)
            .withParameterOfType("ValuePointer", "value", (const void *) null_value_pointer)
            .withParameter("value_length", 0)
            .withParameter("resource_type", LWM2M_OPAQUE)
            .withParameter("opr", OPERATION_READ)
            .withPointerParameter("ctx", connection)
            .andReturnValue(PT_API_SUCCESS);

    mock().expectOneCall("set_resource_value")
            .withStringParameter("endpoint_name", "test-device")
            .withParameter("object_id", 21)
            .withParameter("object_instance_id", 0)
            .withParameter("resource_id", 37)
            .withParameterOfType("ValuePointer", "value", (const void *) string_value_pointer)
            .withParameter("value_length", strlen("test_string"))
            .withParameter("resource_type", LWM2M_STRING)
            .withParameter("opr", OPERATION_READ)
            .withPointerParameter("ctx", connection)
            .andReturnValue(PT_API_SUCCESS);

    mock().expectOneCall("set_resource_value")
            .withStringParameter("endpoint_name", "test-device")
            .withParameter("object_id", 22)
            .withParameter("object_instance_id", 0)
            .withParameter("resource_id", 37)
            .withParameterOfType("ValuePointer", "value", (const void *) int_value_pointer)
            .withParameter("value_length", strlen("100"))
            .withParameter("resource_type", LWM2M_INTEGER)
            .withParameter("opr", OPERATION_READ)
            .withPointerParameter("ctx", connection)
            .andReturnValue(PT_API_SUCCESS);

    mock().expectOneCall("set_resource_value")
            .withStringParameter("endpoint_name", "test-device")
            .withParameter("object_id", 23)
            .withParameter("object_instance_id", 0)
            .withParameter("resource_id", 37)
            .withParameterOfType("ValuePointer", "value", (const void *) float_value_pointer)
            .withParameter("value_length", strlen("0.1"))
            .withParameter("resource_type", LWM2M_FLOAT)
            .withParameter("opr", OPERATION_READ)
            .withPointerParameter("ctx", connection)
            .andReturnValue(PT_API_SUCCESS);

    mock().expectOneCall("set_resource_value")
            .withStringParameter("endpoint_name", "test-device")
            .withParameter("object_id", 24)
            .withParameter("object_instance_id", 0)
            .withParameter("resource_id", 37)
            .withParameterOfType("ValuePointer", "value", (const void *) bool_value_pointer)
            .withParameter("value_length", strlen("true"))
            .withParameter("resource_type", LWM2M_BOOLEAN)
            .withParameter("opr", OPERATION_READ)
            .withPointerParameter("ctx", connection)
            .andReturnValue(PT_API_SUCCESS);

    mock().expectOneCall("set_resource_value")
            .withStringParameter("endpoint_name", "test-device")
            .withParameter("object_id", 25)
            .withParameter("object_instance_id", 0)
            .withParameter("resource_id", 37)
            .withParameterOfType("ValuePointer", "value", (const void *) opq1_value_pointer)
            .withParameter("value_length", strlen("opaque 1"))
            .withParameter("resource_type", LWM2M_OPAQUE)
            .withParameter("opr", OPERATION_READ)
            .withPointerParameter("ctx", connection)
            .andReturnValue(PT_API_SUCCESS);

    mock().expectOneCall("set_resource_value")
            .withStringParameter("endpoint_name", "test-device")
            .withParameter("object_id", 26)
            .withParameter("object_instance_id", 0)
            .withParameter("resource_id", 37)
            .withParameterOfType("ValuePointer", "value", (const void *) time_value_pointer)
            .withParameter("value_length", strlen("1505114436"))
            .withParameter("resource_type",LWM2M_TIME)
            .withParameter("opr", OPERATION_READ)
            .withPointerParameter("ctx", connection)
            .andReturnValue(PT_API_SUCCESS);

    mock().expectOneCall("set_resource_value")
            .withStringParameter("endpoint_name", "test-device")
            .withParameter("object_id", 27)
            .withParameter("object_instance_id", 0)
            .withParameter("resource_id", 37)
            .withParameterOfType("ValuePointer", "value", (const void *) opq2_value_pointer)
            .withParameter("value_length", strlen("opaque 2"))
            .withParameter("resource_type", LWM2M_OPAQUE)
            .withParameter("opr", OPERATION_READ)
            .withPointerParameter("ctx", connection)
            .andReturnValue(PT_API_SUCCESS);

    mock().expectOneCall("set_resource_value")
            .withStringParameter("endpoint_name", "test-device")
            .withParameter("object_id", 28)
            .withParameter("object_instance_id", 0)
            .withParameter("resource_id", 37)
            .withParameterOfType("ValuePointer", "value", (const void *) opq3_value_pointer)
            .withParameter("value_length", strlen("opaque 3"))
            .withParameter("resource_type", LWM2M_OPAQUE)
            .withParameter("opr", OPERATION_READ)
            .withPointerParameter("ctx", connection)
            .andReturnValue(PT_API_SUCCESS);

    mock().expectOneCall("set_resource_value")
            .withStringParameter("endpoint_name", "test-device")
            .withParameter("object_id", 29)
            .withParameter("object_instance_id", 0)
            .withParameter("resource_id", 37)
            .withParameterOfType("ValuePointer", "value", (const void *) opq4_value_pointer)
            .withParameter("value_length", strlen("opaque 5"))
            .withParameter("resource_type", LWM2M_OPAQUE)
            .withParameter("opr", OPERATION_READ)
            .withPointerParameter("ctx", connection)
            .andReturnValue(PT_API_SUCCESS);

    value_pointer_entry_t *null_value_pointer_entry = (value_pointer_entry_t*) calloc(1, sizeof(value_pointer_entry_t));
    null_value_pointer_entry->value_pointer = null_value_pointer;
    ns_list_add_to_end(&_value_pointers, null_value_pointer_entry);

    value_pointer_entry_t *string_value_pointer_entry = (value_pointer_entry_t*) calloc(1, sizeof(value_pointer_entry_t));
    string_value_pointer_entry->value_pointer = string_value_pointer;
    ns_list_add_to_end(&_value_pointers, string_value_pointer_entry);

    value_pointer_entry_t *int_value_pointer_entry = (value_pointer_entry_t*) calloc(1, sizeof(value_pointer_entry_t));
    int_value_pointer_entry->value_pointer = int_value_pointer;
    ns_list_add_to_end(&_value_pointers, int_value_pointer_entry);

    value_pointer_entry_t *float_value_pointer_entry = (value_pointer_entry_t*) calloc(1, sizeof(value_pointer_entry_t));
    float_value_pointer_entry->value_pointer = float_value_pointer;
    ns_list_add_to_end(&_value_pointers, float_value_pointer_entry);

    value_pointer_entry_t *bool_value_pointer_entry = (value_pointer_entry_t*) calloc(1, sizeof(value_pointer_entry_t));
    bool_value_pointer_entry->value_pointer = bool_value_pointer;
    ns_list_add_to_end(&_value_pointers, bool_value_pointer_entry);

    value_pointer_entry_t *time_value_pointer_entry = (value_pointer_entry_t*) calloc(1, sizeof(value_pointer_entry_t));
    time_value_pointer_entry->value_pointer = time_value_pointer;
    ns_list_add_to_end(&_value_pointers, time_value_pointer_entry);

    value_pointer_entry_t *opq1_value_pointer_entry = (value_pointer_entry_t*) calloc(1, sizeof(value_pointer_entry_t));
    opq1_value_pointer_entry->value_pointer = opq1_value_pointer;
    ns_list_add_to_end(&_value_pointers, opq1_value_pointer_entry);

    value_pointer_entry_t *opq2_value_pointer_entry = (value_pointer_entry_t*) calloc(1, sizeof(value_pointer_entry_t));
    opq2_value_pointer_entry->value_pointer = opq2_value_pointer;
    ns_list_add_to_end(&_value_pointers, opq2_value_pointer_entry);

    value_pointer_entry_t *opq3_value_pointer_entry = (value_pointer_entry_t*) calloc(1, sizeof(value_pointer_entry_t));
    opq3_value_pointer_entry->value_pointer = opq3_value_pointer;
    ns_list_add_to_end(&_value_pointers, opq3_value_pointer_entry);

    value_pointer_entry_t *opq4_value_pointer_entry = (value_pointer_entry_t*) calloc(1, sizeof(value_pointer_entry_t));
    opq4_value_pointer_entry->value_pointer = opq4_value_pointer;
    ns_list_add_to_end(&_value_pointers, opq4_value_pointer_entry);
}

/**
 * Mock support for Edge Client response callback
 */
void edgeclient_response_handler_success_test_mock(edgeclient_request_context_t *ctx)
{
    mock().actualCall("edgeclient_response_success_handler")
        .withPointerParameter("ctx", ctx);
}

void edgeclient_response_handler_failure_test_mock(edgeclient_request_context_t *ctx)
{
    mock().actualCall("edgeclient_response_failure_handler")
        .withPointerParameter("ctx", ctx);
}


static void common_setup()
{
    rpc_set_generate_msg_id(test_msg_generate_id);
    eventOS_mock_init();
}

static void common_teardown()
{
    mock().checkExpectations();
    free_value_pointers();
    eventOS_mock_destroy();
    crypto_api_protocol_destroy();
}

/**
 * Test definitions
 */
TEST_GROUP(protocol_api) {
    void setup()
    {
        common_setup();
        create_program_context_and_data();
        struct event_base *base = NULL;
        base = evbase_mock_new();
        int lock_fd = TEST_LOCK_FILE_DESCRIPTOR_ID;
        g_program_context->ev_base = base;
        mock().expectOneCall("edge_io_acquire_lock_for_socket")
                .withStringParameter("path", TEST_UNIX_SOCKET_PATH)
                .withOutputParameterReturning("lock_fd", &lock_fd, sizeof(int))
                .andReturnValue(true);
        mock().expectOneCall("edge_io_file_exists")
                .withStringParameter("path", TEST_UNIX_SOCKET_PATH)
                .andReturnValue(true);
        mock().expectOneCall("edge_io_unlink")
                .withStringParameter("path", TEST_UNIX_SOCKET_PATH)
                .andReturnValue(0);
        mock().expectOneCall("eventOS_scheduler_mutex_wait");
        mock().expectOneCall("eventOS_event_handler_create")
                .withPointerParameter("handler_func_ptr", (void *) crypto_api_event_handler)
                .withIntParameter("init_event_type", CRYPTO_API_EVENT_INIT)
                .andReturnValue(0);
        mock().expectOneCall("eventOS_scheduler_mutex_release");
        crypto_api_protocol_init();

        mock().expectOneCall("lws_create_context");
        int output_lock_fd;
        initialize_libwebsocket_context(base, TEST_UNIX_SOCKET_PATH, edge_server_protocols, &output_lock_fd);
    }

    void teardown()
    {
        common_teardown();
        evbase_mock_delete(g_program_context->ev_base);
        g_program_context->ev_base = NULL;
        mock().expectOneCall("lws_context_destroy");
        mock().expectOneCall("edge_io_release_lock_for_socket")
                .withStringParameter("path", TEST_UNIX_SOCKET_PATH)
                .withIntParameter("lock_fd", TEST_LOCK_FILE_DESCRIPTOR_ID)
                .andReturnValue(true);
        mock().expectOneCall("edge_io_unlink")
                .withStringParameter("path", TEST_UNIX_SOCKET_PATH)
                .andReturnValue(0);
        mock().expectOneCall("edgeclient_destroy");

        expect_mutexing();
        mock().expectOneCall("edge_mutex_destroy").withPointerParameter("mutex", (void *) &rpc_mutex).andReturnValue(0);
        int lock_fd = TEST_LOCK_FILE_DESCRIPTOR_ID;
        clean_resources(lws_mock_get_context(), TEST_UNIX_SOCKET_PATH, lock_fd);
    }
};

TEST_GROUP(protocol_api_without_dummy_program_context) {
    void setup()
    {
        common_setup();
    }

    void teardown()
    {
        common_teardown();
    }
};


TEST(protocol_api, test_register_protocol_translator_missing_id_in_message)
{

    struct test_context *test_ctx = connection_initialized();

    json_t *request = json_object();
    json_t *params = json_object();
    json_object_set_new(request, "jsonrpc", json_string("2.0"));
    json_object_set_new(request, "method", json_string("protocol_translator_register"));
    json_object_set_new(request, "params", params);
    json_object_set_new(params, "name", json_string("TEST-PT"));

    char *data = json_dumps(request, JSON_COMPACT);
    struct json_message_t *userdata = alloc_json_message_t(data, strlen(data), test_ctx->connection);
    free(data);

    json_t *result=NULL;

    mock().expectOneCall("edgeclient_is_shutting_down").andReturnValue(false);
    int rc = protocol_translator_register(request, params, &result, userdata);
    json_t *code_obj = json_object_get(result, "code");
    CHECK_EQUAL(JSONRPC_INVALID_PARAMS, json_integer_value(code_obj));
    CHECK_EQUAL(1, rc);
    CHECK(result != NULL);
    CHECK(test_ctx->connection->connected == false);
    json_t *message_obj = json_object_get(result, "data");
    STRCMP_EQUAL("Protocol translator registration failed. Request id missing.", json_string_value(message_obj));

    json_decref(request);
    json_decref(result);
    deallocate_json_message_t(userdata);

    check_remove_resources_and_objects_owned_by_client(test_ctx->connection, 0 /* endpoints */);
    free_test_context(test_ctx, 0 /* registered_translators*/, 0 /* not_accepted_translators */, 0 /* endpoints */);
    mock().checkExpectations();
}

TEST(protocol_api, test_register_protocol_translator_missing_name_in_message)
{
    struct test_context *test_ctx = connection_initialized();

    json_t *request = json_object();
    json_t *params = json_object();
    json_object_set_new(request, "jsonrpc", json_string("2.0"));
    json_object_set_new(request, "id", json_string("1"));
    json_object_set_new(request, "method", json_string("protocol_translator_register"));
    json_object_set_new(request, "params", params);

    char *data = json_dumps(request, JSON_COMPACT);
    struct json_message_t *userdata = alloc_json_message_t(data, strlen(data), test_ctx->connection);
    free(data);

    json_t *result = NULL;

    mock().expectOneCall("edgeclient_is_shutting_down").andReturnValue(false);
    int rc = protocol_translator_register(request, params, &result, userdata);
    CHECK_EQUAL(rc, 1);
    CHECK(test_ctx->connection->connected == false);

    CHECK(result != NULL);
    json_t *code_obj = json_object_get(result, "code");
    CHECK_EQUAL((int32_t) JSONRPC_INVALID_PARAMS, (int32_t) json_integer_value(code_obj));

    json_t *message_obj = json_object_get(result, "message");
    STRCMP_EQUAL("Invalid params", json_string_value(message_obj));

    json_t *data_obj = json_object_get(result, "data");
    STRCMP_EQUAL("Key 'name' missing", json_string_value(data_obj));
    json_decref(request);
    json_decref(result);

    deallocate_json_message_t(userdata);
    check_remove_resources_and_objects_owned_by_client(test_ctx->connection, 0 /* endpoints */);
    free_test_context(test_ctx, 0 /* registered_translators*/, 0 /* not_accepted_translators */, 0 /* endpoints */);
    mock().checkExpectations();
}

TEST(protocol_api, test_register_protocol_translator_empty_name_in_message)
{
    struct test_context *test_ctx = connection_initialized();

    json_t *request = json_object();
    json_t *params = json_object();
    json_object_set_new(request, "jsonrpc", json_string("2.0"));
    json_object_set_new(request, "id", json_string("1"));
    json_object_set_new(request, "method", json_string("protocol_translator_register"));
    json_object_set_new(request, "params", params);
    json_object_set_new(params, "name", json_null());

    char *data = json_dumps(request, JSON_COMPACT);
    struct json_message_t *userdata = alloc_json_message_t(data, strlen(data), test_ctx->connection);
    free(data);

    json_t *result;

    mock().expectOneCall("edgeclient_is_shutting_down").andReturnValue(false);
    int rc = protocol_translator_register(request, params, &result, userdata);
    CHECK_EQUAL(rc, 1);
    CHECK(test_ctx->connection->connected == false);

    json_t *message_obj = json_object_get(result, "message");
    STRCMP_EQUAL("Invalid params", json_string_value(message_obj));

    json_t *data_obj = json_object_get(result, "data");
    STRCMP_EQUAL("Value for key 'name' missing or empty", json_string_value(data_obj));

    json_decref(request);
    json_decref(result);

    deallocate_json_message_t(userdata);
    check_remove_resources_and_objects_owned_by_client(test_ctx->connection, 0 /* endpoints */);
    free_test_context(test_ctx, 0 /* registered_translators*/, 0 /* not_accepted_translators */, 0 /* endpoints */);
    mock().checkExpectations();
}

TEST(protocol_api, test_register_protocol_translator_already_registered)
{
    struct test_context *test_ctx = connection_initialized();
    test_ctx->connection->client_data->registered = true;

    json_t *request = json_object();
    json_t *params = json_object();
    json_object_set_new(request, "jsonrpc", json_string("2.0"));
    json_object_set_new(request, "id", json_string("1"));
    json_object_set_new(request, "method", json_string("protocol_translator_register"));
    json_object_set_new(request, "params", params);
    json_object_set_new(params, "name", json_string("TEST-PT"));

    char *data = json_dumps(request, JSON_COMPACT);

    struct json_message_t *userdata = alloc_json_message_t(data, strlen(data), test_ctx->connection);
    free(data);

    json_t *result;
    mock().expectOneCall("edgeclient_is_shutting_down").andReturnValue(false);
    int rc = protocol_translator_register(request, params, &result, userdata);
    CHECK_EQUAL(1, rc);
    CHECK(test_ctx->connection->connected == false);

    CHECK(result != NULL);
    json_t *code_obj = json_object_get(result, "code");
    CHECK_EQUAL(PT_API_PROTOCOL_TRANSLATOR_ALREADY_REGISTERED, json_integer_value(code_obj));

    json_t *message_obj = json_object_get(result, "message");
    STRCMP_EQUAL("Protocol translator already registered.", json_string_value(message_obj));

    json_decref(request);
    json_decref(result);
    deallocate_json_message_t(userdata);

    check_remove_resources_and_objects_owned_by_client(test_ctx->connection, 0 /* endpoints */);
    free_test_context(test_ctx, 0 /* registered_translators*/, 0 /* not_accepted_translators */, 0 /* endpoints */);
    mock().checkExpectations();
}

TEST(protocol_api, test_register_protocol_translator_with_same_name_twice)
{
    //First registration attempt
    struct context *context = g_program_context;
    struct ctx_data *ctx_data = (struct ctx_data *)context->ctx_data;
    ns_list_init(&ctx_data->registered_translators);
    ns_list_init(&ctx_data->not_accepted_translators);

    client_data_t *client_data_1 = edge_core_create_client(PT);
    client_data_t *client_data_2 = edge_core_create_client(PT);

    struct connection *first_connection = connection_init(context, client_data_1);
    struct connection *second_connection = connection_init(context, client_data_2);

    json_t *request = json_object();
    json_t *params = json_object();
    json_object_set_new(request, "jsonrpc", json_string("2.0"));
    json_object_set_new(request, "id", json_string("0"));
    json_object_set_new(request, "method", json_string("protocol_translator_register"));
    json_object_set_new(request, "params", params);
    json_object_set_new(params, "name", json_string("TEST-PT"));

    char *data = json_dumps(request, JSON_COMPACT);
    struct json_message_t *userdata = alloc_json_message_t(data, strlen(data), first_connection);
    free(data);

    ValuePointer* pt_name_vp = new ValuePointer((uint8_t*) "TEST-PT", strlen("TEST-PT"));
    value_pointer_entry_t* pt_name_entry = (value_pointer_entry_t*) calloc(1, sizeof(value_pointer_entry_t));
    pt_name_entry->value_pointer = pt_name_vp;
    ns_list_add_to_end(&_value_pointers, pt_name_entry);

    mock().expectOneCall("edgeclient_is_shutting_down").andReturnValue(false);
    mock().expectOneCall("set_resource_value")
            .withStringParameter("endpoint_name", NULL)
            .withParameter("object_id", PROTOCOL_TRANSLATOR_OBJECT_ID)
            .withParameter("object_instance_id", 0)
            .withParameter("resource_id", PROTOCOL_TRANSLATOR_OBJECT_NAME_RESOURCE_ID)
            .withParameterOfType("ValuePointer", "value", (const void *) pt_name_vp)
            .withParameter("value_length", strlen("TEST-PT"))
            .withParameter("resource_type", LWM2M_OPAQUE)
            .withParameter("opr", OPERATION_READ)
            .withPointerParameter("ctx", NULL)
            .andReturnValue(PT_API_SUCCESS);

    // 0 value as registered devices for both translator resources
    uint16_t zero = 0;
    ValuePointer* pt_count_vp = new ValuePointer((uint8_t*) &zero, sizeof(uint16_t));
    value_pointer_entry_t* pt_count_entry = (value_pointer_entry_t*) calloc(1, sizeof(value_pointer_entry_t));
    pt_count_entry->value_pointer = pt_count_vp;
    ns_list_add_to_end(&_value_pointers, pt_count_entry);

    mock().expectOneCall("edgeclient_is_shutting_down").andReturnValue(false);
    mock().expectOneCall("set_resource_value")
            .withStringParameter("endpoint_name", NULL)
            .withParameter("object_id", PROTOCOL_TRANSLATOR_OBJECT_ID)
            .withParameter("object_instance_id", 0)
            .withParameter("resource_id", PROTOCOL_TRANSLATOR_OBJECT_COUNT_RESOURCE_ID)
            .withParameterOfType("ValuePointer", "value", (const void *) pt_count_vp)
            .withParameter("value_length", sizeof(uint16_t))
            .withParameter("resource_type", LWM2M_INTEGER)
            .withParameter("opr", OPERATION_READ)
            .withPointerParameter("ctx", NULL)
            .andReturnValue(PT_API_SUCCESS);

    mock().expectOneCall("update_register_client_conditional");

    json_t *result;
    int rc = protocol_translator_register(request, params, &result, userdata);
    CHECK_EQUAL(0, rc);
    CHECK(userdata->connection->client_data->registered);

    CHECK(result != NULL);
    STRCMP_EQUAL("ok", json_string_value(result));

    deallocate_json_message_t(userdata);
    json_decref(result);

    //Second registration attempt

    data = json_dumps(request, JSON_COMPACT);
    userdata = alloc_json_message_t(data, strlen(data), second_connection);
    free(data);

    rc = protocol_translator_register(request, params, &result, userdata);
    CHECK_EQUAL(1, rc);

    CHECK(result != NULL);
    json_t *message_obj = json_object_get(result, "message");
    STRCMP_EQUAL("Protocol translator name reserved.", json_string_value(message_obj));
    json_t *data_obj = json_object_get(result, "data");
    STRCMP_EQUAL("Cannot register the protocol translator.", json_string_value(data_obj));
    CHECK(second_connection->connected == false);

    json_decref(request);
    json_decref(result);

    check_connection_free_expectations(first_connection, 26241, 0, 0 /* endpoints */);
    CHECK_EQUAL(0, connection_free(first_connection));

    check_remove_resources_and_objects_owned_by_client(second_connection, 0 /* endpoints */);
    CHECK_EQUAL(0, connection_free(second_connection));

    deallocate_json_message_t(userdata);
    check_context(context,
                  1 /* registered_translators*/,
                  1 /* not_accepted_translators */,
                  0 /* registered_endpoints */);
    mock().checkExpectations();
}

TEST(protocol_api, test_register_protocol_translators_with_different_names)
{
    // 0 value as registered devices for both translator resources
    uint16_t zero = 0;
    ValuePointer pt_count_vp = ValuePointer((uint8_t*) &zero, sizeof(uint16_t));

    //First registration
    struct context *context = g_program_context;
    struct ctx_data *ctx_data = (struct ctx_data *)context->ctx_data;
    ns_list_init(&ctx_data->registered_translators);

    client_data_t *client_data = edge_core_create_client(PT);
    client_data_t *client_data_2 = edge_core_create_client(PT);

    struct connection *first_connection = connection_init(context, client_data);

    json_t *request = json_object();
    json_t *params = json_object();
    json_object_set_new(request, "jsonrpc", json_string("2.0"));
    json_object_set_new(request, "id", json_string("0"));
    json_object_set_new(request, "method", json_string("protocol_translator_register"));
    json_object_set_new(request, "params", params);
    json_object_set_new(params, "name", json_string("TEST-PT"));

    char *data = json_dumps(request, JSON_COMPACT);

    struct json_message_t *userdata = alloc_json_message_t(data, strlen(data), first_connection);
    free(data);

    ValuePointer pt_name_vp_1 = ValuePointer((uint8_t*) "TEST-PT", strlen("TEST-PT"));
    mock().expectOneCall("edgeclient_is_shutting_down").andReturnValue(false);
    mock().expectOneCall("set_resource_value")
            .withStringParameter("endpoint_name", NULL)
            .withParameter("object_id", PROTOCOL_TRANSLATOR_OBJECT_ID)
            .withParameter("object_instance_id", 0)
            .withParameter("resource_id", PROTOCOL_TRANSLATOR_OBJECT_NAME_RESOURCE_ID)
            .withParameterOfType("ValuePointer", "value", &pt_name_vp_1)
            .withParameter("value_length", strlen("TEST-PT"))
            .withParameter("resource_type", LWM2M_OPAQUE)
            .withParameter("opr", OPERATION_READ)
            .withPointerParameter("ctx", NULL)
            .andReturnValue(PT_API_SUCCESS);

    mock().expectOneCall("set_resource_value")
            .withStringParameter("endpoint_name", NULL)
            .withParameter("object_id", PROTOCOL_TRANSLATOR_OBJECT_ID)
            .withParameter("object_instance_id", 0)
            .withParameter("resource_id", PROTOCOL_TRANSLATOR_OBJECT_COUNT_RESOURCE_ID)
            .withParameterOfType("ValuePointer", "value", &pt_count_vp)
            .withParameter("value_length", sizeof(uint16_t))
            .withParameter("resource_type", LWM2M_INTEGER)
            .withParameter("opr", OPERATION_READ)
            .withPointerParameter("ctx", NULL)
            .andReturnValue(PT_API_SUCCESS);

    mock().expectOneCall("update_register_client_conditional");
    mock().expectOneCall("update_register_client_conditional");

    json_t *result;
    int rc = protocol_translator_register(request, params, &result, userdata);
    CHECK_EQUAL(0, rc);
    CHECK(userdata->connection->client_data->registered);

    CHECK(result != NULL);
    STRCMP_EQUAL("ok", json_string_value(result));

    json_decref(request);
    json_decref(result);
    deallocate_json_message_t(userdata);

    //Second registration
    struct connection *second_connection = connection_init(context, client_data_2);

    request = json_object();
    params = json_object();
    json_object_set_new(request, "jsonrpc", json_string("2.0"));
    json_object_set_new(request, "id", json_string("0"));
    json_object_set_new(request, "method", json_string("protocol_translator_register"));
    json_object_set_new(request, "params", params);
    json_object_set_new(params, "name", json_string("TEST-PT-DIFFERENT"));

    data = json_dumps(request, JSON_COMPACT);
    userdata = alloc_json_message_t(data, strlen(data), second_connection);
    free(data);

    ValuePointer pt_name_vp_2 = ValuePointer((uint8_t*) "TEST-PT-DIFFERENT", strlen("TEST-PT-DIFFERENT"));
    mock().expectOneCall("edgeclient_is_shutting_down").andReturnValue(false);
    mock().expectOneCall("set_resource_value")
            .withStringParameter("endpoint_name", NULL)
            .withParameter("object_id", PROTOCOL_TRANSLATOR_OBJECT_ID)
            .withParameter("object_instance_id", 1)
            .withParameter("resource_id", PROTOCOL_TRANSLATOR_OBJECT_NAME_RESOURCE_ID)
            .withParameterOfType("ValuePointer", "value", &pt_name_vp_2)
            .withParameter("value_length", strlen("TEST-PT-DIFFERENT"))
            .withParameter("resource_type", LWM2M_OPAQUE)
            .withParameter("opr", OPERATION_READ)
            .withPointerParameter("ctx", NULL)
            .andReturnValue(PT_API_SUCCESS);

    mock().expectOneCall("set_resource_value")
            .withStringParameter("endpoint_name", NULL)
            .withParameter("object_id", PROTOCOL_TRANSLATOR_OBJECT_ID)
            .withParameter("object_instance_id", 1)
            .withParameter("resource_id", PROTOCOL_TRANSLATOR_OBJECT_COUNT_RESOURCE_ID)
            .withParameterOfType("ValuePointer", "value", &pt_count_vp)
            .withParameter("value_length", sizeof(uint16_t))
            .withParameter("resource_type", LWM2M_INTEGER)
            .withParameter("opr", OPERATION_READ)
            .withPointerParameter("ctx", NULL)
            .andReturnValue(PT_API_SUCCESS);

    rc = protocol_translator_register(request, params, &result, userdata);
    CHECK_EQUAL(0, rc);

    CHECK(result != NULL);
    STRCMP_EQUAL("ok", json_string_value(result));

    json_decref(request);
    json_decref(result);

    deallocate_json_message_t(userdata);

    check_connection_free_expectations(first_connection, 26241, 0, 0 /* endpoints */);
    CHECK_EQUAL(0, connection_free(first_connection));

    check_connection_free_expectations(second_connection, 26241, 1, 0 /* endpoints */);
    CHECK_EQUAL(0, connection_free(second_connection));

    check_context(context,
                  2 /* registered_translators*/,
                  0 /* not_accepted_translators */,
                  0 /* registered_endpoints */);
    mock().checkExpectations();
}

static void test_registers_successfully(struct test_context *test_ctx)
{
    json_t *request = json_object();
    json_t *params = json_object();
    json_object_set_new(request, "jsonrpc", json_string("2.0"));
    json_object_set_new(request, "id", json_string("1"));
    json_object_set_new(request, "method", json_string("protocol_translator_register"));
    json_object_set_new(request, "params", params);
    json_object_set_new(params, "name", json_string("TEST-PT"));

    char *data = json_dumps(request, JSON_COMPACT);
    struct json_message_t *userdata = alloc_json_message_t(data, strlen(data), test_ctx->connection);
    free(data);

    ValuePointer pt_name_vp = ValuePointer((uint8_t*) "TEST-PT", strlen("TEST-PT"));
    mock().expectOneCall("edgeclient_is_shutting_down").andReturnValue(false);
    mock().expectOneCall("set_resource_value")
            .withStringParameter("endpoint_name", NULL)
            .withParameter("object_id", PROTOCOL_TRANSLATOR_OBJECT_ID)
            .withParameter("object_instance_id", 0)
            .withParameter("resource_id", PROTOCOL_TRANSLATOR_OBJECT_NAME_RESOURCE_ID)
            .withParameterOfType("ValuePointer", "value", (const void *) &pt_name_vp)
            .withParameter("value_length", strlen("TEST-PT"))
            .withParameter("resource_type", LWM2M_OPAQUE)
            .withParameter("opr", OPERATION_READ)
            .withPointerParameter("ctx", NULL)
            .andReturnValue(PT_API_SUCCESS);

    uint16_t zero = 0;
    ValuePointer pt_count_vp = ValuePointer((uint8_t*) &zero, sizeof(uint16_t));
    mock().expectOneCall("set_resource_value")
            .withStringParameter("endpoint_name", NULL)
            .withParameter("object_id", PROTOCOL_TRANSLATOR_OBJECT_ID)
            .withParameter("object_instance_id", 0)
            .withParameter("resource_id", PROTOCOL_TRANSLATOR_OBJECT_COUNT_RESOURCE_ID)
            .withParameterOfType("ValuePointer", "value", (const void *) &pt_count_vp)
            .withParameter("value_length", sizeof(uint16_t))
            .withParameter("resource_type", LWM2M_INTEGER)
            .withParameter("opr", OPERATION_READ)
            .withPointerParameter("ctx", NULL)
            .andReturnValue(PT_API_SUCCESS);

    mock().expectOneCall("update_register_client_conditional");


    json_t *result;
    int rc = protocol_translator_register(request, params, &result, userdata);
    CHECK_EQUAL(0, rc);
    CHECK(userdata->connection->client_data->registered);

    CHECK(result != NULL);
    STRCMP_EQUAL("ok", json_string_value(result));
    mock().checkExpectations();

    json_decref(request);
    json_decref(result);

    deallocate_json_message_t(userdata);
}

TEST(protocol_api, test_register_protocol_translator_success)
{
    struct test_context *test_ctx = connection_initialized();
    test_registers_successfully(test_ctx);
    check_connection_free_expectations(test_ctx->connection, 26241, 0, 0 /* endpoints */);
    free_test_context(test_ctx, 1 /* registered_translators*/, 0 /* not_accepted_translators */, 0 /* endpoints */);
    mock().checkExpectations();
}

static void check_connection_free_expectations(struct connection *connection,
                                               int expected_object_id,
                                               int expected_object_instance_id,
                                               uint32_t registered_endpoints)
{
    check_remove_resources_and_objects_owned_by_client(connection, registered_endpoints);
    mock().expectOneCall("remove_object_instance")
            .withStringParameter("endpoint_name", NULL)
            .withParameter("object_id", expected_object_id)
            .withParameter("object_instance_id", expected_object_instance_id);
}

static ValuePointer* check_creates_endpoint_expectations(struct connection *connection,
                                                         struct pt_device_count_expectations *dce) {
    mock().expectOneCall("edgeclient_is_shutting_down").andReturnValue(false);
    mock().expectNCalls(2, "endpoint_exists").withParameter("endpoint_name", "test-device").andReturnValue(0);

    mock().expectOneCall("add_endpoint")
            .withParameter("endpoint_name", "test-device")
            .withParameter("ctx", connection)
            .andReturnValue(1);

    expected_device_register_test_structure(connection);
    mock().expectNCalls(1, "update_register_client_conditional");

    mock().expectOneCall("get_resource_value")
            .withStringParameter("endpoint_name", NULL)
            .withParameter("object_id", PROTOCOL_TRANSLATOR_OBJECT_ID)
            .withParameter("object_instance_id", 0)
            .withParameter("resource_id", PROTOCOL_TRANSLATOR_OBJECT_COUNT_RESOURCE_ID)
            .withOutputParameterReturning("value", &dce->get_resource_value, sizeof(char*))
            .withOutputParameterReturning("value_length", dce->get_value_size, sizeof(uint32_t));

    ValuePointer *value_pointer = new ValuePointer((uint8_t*) dce->set_resource_value, *dce->set_value_size);

    mock().expectOneCall("set_resource_value")
            .withStringParameter("endpoint_name", NULL)
            .withParameter("object_id", PROTOCOL_TRANSLATOR_OBJECT_ID)
            .withParameter("object_instance_id", 0)
            .withParameter("resource_id", PROTOCOL_TRANSLATOR_OBJECT_COUNT_RESOURCE_ID)
            .withParameterOfType("ValuePointer", "value", (const void *) value_pointer)
            .withParameter("value_length", sizeof(uint16_t))
            .withParameter("resource_type", LWM2M_INTEGER)
            .withParameter("opr", OPERATION_READ)
            .withPointerParameter("ctx", connection)
            .andReturnValue(PT_API_SUCCESS);
    mock().expectNCalls(1, "update_register_client_conditional");

    return value_pointer;
}

/*
 * \brief Unregisters endpoint.
 *        Note: result and return value are allocated and need to be freed using json_decref
 *        Note: if endpoint_json_filepath is NULL, no parameters are set.
 */
static struct json_message_t* unregister_endpoint(
        struct connection *connection,
        const char *endpoint_json_filepath,
        int *return_code,
        json_t **result)
{
    // Load device registration jsonrpc parameters structure from file
    json_t *params = NULL;

    if (endpoint_json_filepath) {
        params = load_json_params(endpoint_json_filepath);
    }

    // Build device registration jsonrpc structure
    json_t *request = json_object();
    json_object_set_new(request, "jsonrpc", json_string("2.0"));
    json_object_set_new(request, "id", json_string("1"));
    json_object_set_new(request, "method", json_string("device_unregister"));
    if (params) {
        json_object_set_new(request, "params", params);
    }

    char *data = json_dumps(request, JSON_COMPACT);
    struct json_message_t *userdata = alloc_json_message_t(data, strlen(data), connection);
    free(data);

    *return_code = device_unregister(request, params, result, userdata);
    CHECK(*result != NULL);

    json_decref(request);
    return userdata;
}

TEST(protocol_api, test_device_register_creates_endpoint)
{
    struct test_context *test_ctx = protocol_translator_registered(0);
    struct pt_device_count_expectations *dce_register = pt_create_device_count_expectations("0", 1);

    ValuePointer* pt_resource_vp = check_creates_endpoint_expectations(test_ctx->connection, dce_register);

    struct json_message_t *userdata = create_endpoint(test_ctx->connection, TEST_DEVICE_REGISTER_JSON);

    deallocate_json_message_t(userdata);

    delete pt_resource_vp;
    free_pt_device_count_expectations(dce_register);

    check_connection_free_expectations(test_ctx->connection, 26241, 0, 1 /* endpoints */);
    free_test_context(test_ctx, 0 /* registered_translators*/, 0 /* not_accepted_translators */, 1 /* endpoints */);
    mock().checkExpectations();
}

TEST(protocol_api, test_device_register_object_instance_id_missing)
{
    struct test_context *test_ctx = protocol_translator_registered(0);

    mock().expectOneCall("edgeclient_is_shutting_down").andReturnValue(false);
    mock().expectOneCall("endpoint_exists").withParameter("endpoint_name", "test-device").andReturnValue(0);
    mock().expectOneCall("endpoint_exists").withParameter("endpoint_name", "test-device").andReturnValue(0);

    mock().expectOneCall("add_endpoint")
            .withParameter("endpoint_name", "test-device")
            .withParameter("ctx", test_ctx->connection)
            .andReturnValue(1);
    struct json_message_t
            *userdata = create_endpoint_with_expectations(test_ctx->connection,
                                                          TEST_DEVICE_REGISTER_INVALID_INSTANCE_JSON,
                                                          1,
                                                          "{\"message\":\"Invalid json "
                                                          "structure.\",\"code\":-30103,\"data\":"
                                                          "\"Failed to register device. Reason: "
                                                          "Invalid or missing objectInstanceId key.\"}");

    deallocate_json_message_t(userdata);

    check_connection_free_expectations(test_ctx->connection, 26241, 0, 0 /* endpoints */);
    free_test_context(test_ctx, 0 /* registered_translators*/, 0 /* not_accepted_translators */, 0 /* endpoints */);
    mock().checkExpectations();
}

TEST(protocol_api, test_device_register_with_invalid_value)
{
    ValuePointer *bool_value_pointer = new ValuePointer((uint8_t *) "truetrue", strlen("truetrue"));
    struct test_context *test_ctx = protocol_translator_registered(0);
    value_pointer_entry_t *int_value_pointer_entry = (value_pointer_entry_t *) calloc(1, sizeof(value_pointer_entry_t));
    int_value_pointer_entry->value_pointer = bool_value_pointer;
    ns_list_add_to_end(&_value_pointers, int_value_pointer_entry);

    mock().expectOneCall("edgeclient_is_shutting_down").andReturnValue(false);
    mock().expectOneCall("endpoint_exists").withParameter("endpoint_name", "test-device").andReturnValue(0);
    mock().expectOneCall("endpoint_exists").withParameter("endpoint_name", "test-device").andReturnValue(0);

    mock().expectOneCall("add_endpoint")
            .withParameter("endpoint_name", "test-device")
            .withParameter("ctx", test_ctx->connection)
            .andReturnValue(1);
    mock().expectOneCall("edgeclient_verify_value")
            .withParameterOfType("ValuePointer", "value", (const void *) bool_value_pointer)
            .withParameter("value_length", strlen("truetrue"))
            .withParameter("resource_type", LWM2M_BOOLEAN)
            .andReturnValue(false);
    struct json_message_t
            *userdata = create_endpoint_with_expectations(test_ctx->connection,
                                                          TEST_DEVICE_REGISTER_INVALID_RESOURCE_VALUE_JSON,
                                                          1,
                                                          "{\"message\":\"Illegal value.\",\"code\":-30101,\"data\":"
                                                          "\"Failed to register device.\"}");

    deallocate_json_message_t(userdata);

    check_connection_free_expectations(test_ctx->connection, 26241, 0, 0 /* endpoints */);
    free_test_context(test_ctx, 0 /* registered_translators*/, 0 /* not_accepted_translators */, 0 /* endpoints */);
    mock().checkExpectations();
}

TEST(protocol_api, test_device_register_resource_item_id_missing)
{
    struct test_context *test_ctx = protocol_translator_registered(0);

    mock().expectOneCall("edgeclient_is_shutting_down").andReturnValue(false);
    mock().expectOneCall("endpoint_exists").withParameter("endpoint_name", "test-device").andReturnValue(0);
    mock().expectOneCall("endpoint_exists").withParameter("endpoint_name", "test-device").andReturnValue(0);

    mock().expectOneCall("add_endpoint")
            .withParameter("endpoint_name", "test-device")
            .withParameter("ctx", test_ctx->connection)
            .andReturnValue(1);
    struct json_message_t *userdata = create_endpoint_with_expectations(test_ctx->connection,
                                                                        TEST_DEVICE_REGISTER_INVALID_RESOURCE_JSON,
                                                                        1,
                                                                        "{\"message\":\"Invalid json "
                                                                        "structure.\",\"code\":-30103,\"data\":"
                                                                        "\"Failed to register device. Reason: "
                                                                        "Invalid or missing resource resourceId key.\"}");

    deallocate_json_message_t(userdata);

    check_connection_free_expectations(test_ctx->connection, 26241, 0, 0 /* endpoints */);
    free_test_context(test_ctx, 0 /* registered_translators*/, 0 /* not_accepted_translators */, 0 /* endpoints */);
    mock().checkExpectations();
}

TEST(protocol_api, test_device_register_object_id_missing)
{
    struct test_context *test_ctx = protocol_translator_registered(0);

    mock().expectOneCall("edgeclient_is_shutting_down").andReturnValue(false);
    mock().expectOneCall("endpoint_exists").withParameter("endpoint_name", "test-device").andReturnValue(0);
    mock().expectOneCall("endpoint_exists").withParameter("endpoint_name", "test-device").andReturnValue(0);

    mock().expectOneCall("add_endpoint")
            .withParameter("endpoint_name", "test-device")
            .withParameter("ctx", test_ctx->connection)
            .andReturnValue(1);
    struct json_message_t *userdata = create_endpoint_with_expectations(test_ctx->connection,
                                                                        TEST_DEVICE_REGISTER_INVALID_OBJECT_JSON,
                                                                        1,
                                                                        "{\"message\":\"Invalid json "
                                                                        "structure.\",\"code\":-30103,\"data\":"
                                                                        "\"Failed to register device. Reason: "
                                                                        "Invalid or missing objectId key.\"}");

    deallocate_json_message_t(userdata);

    check_connection_free_expectations(test_ctx->connection, 26241, 0, 0 /* endpoints */);
    free_test_context(test_ctx, 0 /* registered_translators*/, 0 /* not_accepted_translators */, 0 /* endpoints */);
    mock().checkExpectations();
}

static void register_device_with_index(multiple_devices_test_data_t *test_data,
                                       struct test_context *test_ctx,
                                       int32_t device_index,
                                       int32_t counter_index,
                                       const pt_api_result_code_e code)
{
    uint32_t value_len = sizeof(uint16_t);
    json_t *request = json_object();
    json_object_set_new(request, "jsonrpc", json_string("2.0"));
    json_object_set_new(request, "id", json_string("1"));
    json_object_set_new(request, "method", json_string("write"));

    json_t *params = json_object();
    json_object_set_new(request, "params", params);

    char *data = json_dumps(request, JSON_COMPACT);
    struct json_message_t *userdata = alloc_json_message_t(data, strlen(data), test_ctx->connection);
    free(data);

    char *device_id_str = (char*) malloc(20);
    sprintf(device_id_str, "device-%d", device_index);
    json_t *device_id = json_string(device_id_str);
    json_t *lifetime = json_string("3600");
    json_t *queuemode = json_string("Q");

    json_object_set_new(params, "deviceId", device_id);
    json_object_set_new(params, "lifetime", lifetime);
    json_object_set_new(params, "queuemode", queuemode);

    mock().expectOneCall("edgeclient_is_shutting_down").andReturnValue(false);
    mock().expectOneCall("endpoint_exists").withParameter("endpoint_name", device_id_str).andReturnValue(0);

    if (code == PT_API_SUCCESS) {
        mock().expectOneCall("endpoint_exists").withParameter("endpoint_name", device_id_str).andReturnValue(0);
        mock().expectOneCall("add_endpoint")
                .withParameter("endpoint_name", device_id_str)
                .withParameter("ctx", test_ctx->connection)
                .andReturnValue(1);
        mock().expectOneCall("update_register_client_conditional");

        mock().expectOneCall("get_resource_value")
                .withStringParameter("endpoint_name", NULL)
                .withParameter("object_id", PROTOCOL_TRANSLATOR_OBJECT_ID)
                .withParameter("object_instance_id", 0)
                .withParameter("resource_id", PROTOCOL_TRANSLATOR_OBJECT_COUNT_RESOURCE_ID)
                .withOutputParameterReturning(
                        "value", &(test_data->pt_device_amount_read[counter_index]), sizeof(uint16_t *))
                .withOutputParameterReturning("value_length", &value_len, sizeof(uint32_t));

        ValuePointer *value_pointer =
                new ValuePointer((uint8_t *) (test_data->pt_device_amount_set[counter_index]), value_len);
        test_data->value_pointers[counter_index] = value_pointer;

        mock().expectOneCall("set_resource_value")
                .withStringParameter("endpoint_name", NULL)
                .withParameter("object_id", PROTOCOL_TRANSLATOR_OBJECT_ID)
                .withParameter("object_instance_id", 0)
                .withParameter("resource_id", PROTOCOL_TRANSLATOR_OBJECT_COUNT_RESOURCE_ID)
                .withParameterOfType("ValuePointer", "value", (const void *) value_pointer)
                .withParameter("value_length", sizeof(uint16_t))
                .withParameter("resource_type", LWM2M_INTEGER)
                .withParameter("opr", OPERATION_READ)
                .withPointerParameter("ctx", test_ctx->connection)
                .andReturnValue(PT_API_SUCCESS);
        mock().expectOneCall("update_register_client_conditional");
    }

    json_t *result = NULL;
    int rc = device_register(request, params, &result, userdata);
    free(device_id_str);

    if (code == PT_API_SUCCESS) {
        CHECK_EQUAL(0, rc);
    } else if (code == PT_API_REGISTERED_ENDPOINT_LIMIT_REACHED) {
        CHECK_EQUAL(1, rc);

        CHECK(result != NULL);
        json_t *code_obj = json_object_get(result, "code");
        CHECK_EQUAL(PT_API_REGISTERED_ENDPOINT_LIMIT_REACHED, (int32_t) json_integer_value(code_obj));

        json_t *message_obj = json_object_get(result, "message");
        STRCMP_EQUAL("The maximum number of registered endpoints is already in use.", json_string_value(message_obj));

        json_t *data_obj = json_object_get(result, "data");
        STRCMP_EQUAL("Failed to register device.", json_string_value(data_obj));
    } else {
        CHECK_EQUAL(PT_API_SUCCESS, (int32_t) code); // Unexpected return code
    }

    json_decref(request);
    json_decref(result);

    deallocate_json_message_t(userdata);

}

static void unregister_device_with_index(multiple_devices_test_data_t *test_data,
                                         struct test_context *test_ctx,
                                         int32_t device_index,
                                         int32_t counter_index)
{
    uint32_t value_len = sizeof(uint16_t);
    char device_name[30];
    // Build device unregistration jsonrpc structure
    sprintf(device_name, "test-device-%d", device_index);
    json_t *request = json_object();
    json_object_set_new(request, "jsonrpc", json_string("2.0"));
    json_object_set_new(request, "method", json_string("device_unregister"));
    json_object_set_new(request, "id", json_string("1"));

    json_t *params = json_object();
    json_object_set_new(params, "deviceId", json_string(device_name));
    json_object_set_new(request, "params", params);

    char *data = json_dumps(request, JSON_COMPACT);
    struct json_message_t *userdata = alloc_json_message_t(data, strlen(data), test_ctx->connection);
    free(data);

    mock().expectOneCall("edgeclient_is_shutting_down").andReturnValue(false);
    /* Check for pending requests */
    mock().expectOneCall("endpoint_exists").withStringParameter("endpoint_name", device_name).andReturnValue(1);
    mock().expectOneCall("edge_mutex_lock").withPointerParameter("mutex", (void *) &rpc_mutex).andReturnValue(0);
    mock().expectOneCall("edge_mutex_unlock").withPointerParameter("mutex", (void *) &rpc_mutex).andReturnValue(0);
    mock().expectOneCall("remove_endpoint").withStringParameter("endpoint_name", device_name).andReturnValue(true);
    mock().expectOneCall("get_resource_value")
            .withStringParameter("endpoint_name", NULL)
            .withParameter("object_id", PROTOCOL_TRANSLATOR_OBJECT_ID)
            .withParameter("object_instance_id", 0)
            .withParameter("resource_id", PROTOCOL_TRANSLATOR_OBJECT_COUNT_RESOURCE_ID)
            .withOutputParameterReturning(
                    "value", &(test_data->pt_device_amount_read[counter_index]), sizeof(uint16_t *))
            .withOutputParameterReturning("value_length", &value_len, sizeof(uint32_t));

    ValuePointer *value_pointer =
            new ValuePointer((uint8_t *) (test_data->pt_device_amount_set[counter_index]), value_len);
    test_data->value_pointers[counter_index] = value_pointer;

    mock().expectOneCall("set_resource_value")
            .withStringParameter("endpoint_name", NULL)
            .withParameter("object_id", PROTOCOL_TRANSLATOR_OBJECT_ID)
            .withParameter("object_instance_id", 0)
            .withParameter("resource_id", PROTOCOL_TRANSLATOR_OBJECT_COUNT_RESOURCE_ID)
            .withParameterOfType("ValuePointer", "value", (const void *) value_pointer)
            .withParameter("value_length", sizeof(uint16_t))
            .withParameter("resource_type", LWM2M_INTEGER)
            .withParameter("opr", OPERATION_READ)
            .withPointerParameter("ctx", test_ctx->connection)
            .andReturnValue(PT_API_SUCCESS);

    mock().expectOneCall("update_register_client_conditional");

    json_t *result;
    int rc = device_unregister(request, params, &result, userdata);
    CHECK_EQUAL(0, rc);

    json_decref(request);
    json_decref(result);

    deallocate_json_message_t(userdata);
}

TEST(protocol_api, test_device_register_fails_when_endpoint_limit_is_reached)
{
    struct test_context *test_ctx = protocol_translator_registered(0);
    int16_t i;
    multiple_devices_test_data_t data;
    alloc_multiple_devices_test_data(&data, 12);
    for (i = 0; i < 10; i++) {
        int16_t cur_num = i + 10;
        size_t buffer_len = integer_to_text_format(cur_num, NULL, 0) + 1;
        data.pt_device_amount_read[i] = (char*) calloc(buffer_len, sizeof(char));;
        integer_to_text_format(cur_num, data.pt_device_amount_read[i], buffer_len);
        *(data.pt_device_amount_set[i]) = htons(i + 11);
    }
    data.pt_device_amount_read[10] = strdup("10");
    *(data.pt_device_amount_set[10]) = htons(9);
    data.pt_device_amount_read[11] = strdup("9");
    *(data.pt_device_amount_set[11]) = htons(10);

    edgeserver_set_number_registered_endpoints_limit(10);
    for (i = 0; i < 10; i++) {
        register_device_with_index(&data, test_ctx, i, i, PT_API_SUCCESS);
    }
    register_device_with_index(&data, test_ctx, 10, 10, PT_API_REGISTERED_ENDPOINT_LIMIT_REACHED);
    unregister_device_with_index(&data, test_ctx, 1, 10);
    register_device_with_index(&data, test_ctx, 11, 11, PT_API_SUCCESS);
    free_multiple_devices_test_data(&data);
    check_connection_free_expectations(test_ctx->connection, 26241, 0, 10 /* endpoints */);
    free_test_context(test_ctx, 0, 0, 10 /* endpoints */);
    mock().checkExpectations();
}

TEST(protocol_api, test_register_already_registered_device)
{
    struct test_context *test_ctx = protocol_translator_registered(1);
    check_connection_free_expectations(test_ctx->connection, 26241, 1, 0 /* endpoints */);
    // Build device registration jsonrpc structure
    json_t *request = json_object();
    json_object_set_new(request, "jsonrpc", json_string("2.0"));
    json_object_set_new(request, "method", json_string("device_register"));
    json_object_set_new(request, "id", json_string("1"));

    json_t *params = json_object();
    json_object_set_new(params, "deviceId", json_string("test-device"));
    json_object_set_new(request, "params", params);

    char *data = json_dumps(request, JSON_COMPACT);
    struct json_message_t *userdata = alloc_json_message_t(data, strlen(data), test_ctx->connection);
    free(data);

    mock().expectOneCall("edgeclient_is_shutting_down").andReturnValue(false);
    mock().expectOneCall("endpoint_exists").withParameter("endpoint_name", "test-device").andReturnValue(1);

    json_t *result;
    int rc = device_register(request, params, &result, userdata);
    CHECK_EQUAL(1, rc);

    CHECK(result != NULL);
    json_t *code_obj = json_object_get(result, "code");
    CHECK_EQUAL(PT_API_ENDPOINT_ALREADY_REGISTERED, (int32_t) json_integer_value(code_obj));

    json_t *message_obj = json_object_get(result, "message");
    STRCMP_EQUAL("Cannot register endpoint, because it's already registered.", json_string_value(message_obj));

    json_t *data_obj = json_object_get(result, "data");
    STRCMP_EQUAL("Device already registered.",
                 json_string_value(data_obj));

    json_decref(request);
    json_decref(result);

    deallocate_json_message_t(userdata);
    free_test_context(test_ctx, 0, 0, 0 /* endpoints */);
    mock().checkExpectations();
}

TEST(protocol_api, test_register_already_registered_device_max_limit_reached)
{
    struct test_context *test_ctx = protocol_translator_registered(1);
    check_connection_free_expectations(test_ctx->connection, 26241, 1, 0 /* endpoints */);
    edgeserver_set_number_registered_endpoints_limit(0); // make sure we're maxed out
    // Build device registration jsonrpc structure
    json_t *request = json_object();
    json_object_set_new(request, "jsonrpc", json_string("2.0"));
    json_object_set_new(request, "method", json_string("device_register"));
    json_object_set_new(request, "id", json_string("1"));

    json_t *params = json_object();
    json_object_set_new(params, "deviceId", json_string("test-device"));
    json_object_set_new(request, "params", params);

    char *data = json_dumps(request, JSON_COMPACT);
    struct json_message_t *userdata = alloc_json_message_t(data, strlen(data), test_ctx->connection);
    free(data);

    mock().expectOneCall("edgeclient_is_shutting_down").andReturnValue(false);
    mock().expectOneCall("endpoint_exists").withParameter("endpoint_name", "test-device").andReturnValue(1);

    json_t *result;
    int rc = device_register(request, params, &result, userdata);
    CHECK_EQUAL(1, rc);

    CHECK(result != NULL);
    json_t *code_obj = json_object_get(result, "code");
    CHECK_EQUAL(PT_API_ENDPOINT_ALREADY_REGISTERED, (int32_t) json_integer_value(code_obj));

    json_t *message_obj = json_object_get(result, "message");
    STRCMP_EQUAL("Cannot register endpoint, because it's already registered.", json_string_value(message_obj));

    json_t *data_obj = json_object_get(result, "data");
    STRCMP_EQUAL("Device already registered.",
                 json_string_value(data_obj));

    json_decref(request);
    json_decref(result);

    deallocate_json_message_t(userdata);
    free_test_context(test_ctx, 0, 0, 0 /* endpoints */);
    mock().checkExpectations();
}

TEST(protocol_api, test_device_register_fails_when_endpoint_cannot_be_created)
{
    struct test_context *test_ctx = protocol_translator_registered(1);

    // Build device registration jsonrpc structure
    json_t *request = json_object();
    json_object_set_new(request, "jsonrpc", json_string("2.0"));
    json_object_set_new(request, "id", json_string("1"));
    json_object_set_new(request, "method", json_string("device_register"));

    json_t *params = json_object();
    json_object_set_new(params, "deviceId", json_string("test-device"));
    json_object_set_new(request, "params", params);

    char *data = json_dumps(request, JSON_COMPACT);
    struct json_message_t *userdata = alloc_json_message_t(data, strlen(data), test_ctx->connection);
    free(data);

    mock().expectOneCall("edgeclient_is_shutting_down").andReturnValue(false);
    mock().expectOneCall("endpoint_exists")
        .withParameter("endpoint_name", "test-device")
        .andReturnValue(0);

    mock().expectOneCall("add_endpoint")
        .withParameter("endpoint_name", "test-device")
        .withParameter("ctx", test_ctx->connection)
        .andReturnValue(0);

    json_t *result;
    mock().expectOneCall("endpoint_exists").withParameter("endpoint_name", "test-device").andReturnValue(0);
    int rc = device_register(request, params, &result, userdata);
    CHECK_EQUAL(1, rc);

    CHECK(result != NULL);

    json_t *code_obj = json_object_get(result, "code");
    CHECK_EQUAL(PT_API_INTERNAL_ERROR, (int32_t) json_integer_value(code_obj));

    json_t *message_obj = json_object_get(result, "message");
    STRCMP_EQUAL("Protocol translator API internal error.", json_string_value(message_obj));

    json_t *data_obj = json_object_get(result, "data");
    STRCMP_EQUAL("Failed to register device.", json_string_value(data_obj));

    json_decref(request);
    json_decref(result);

    deallocate_json_message_t(userdata);

    check_connection_free_expectations(test_ctx->connection, 26241, 1, 0 /* endpoints */);
    free_test_context(test_ctx, 0, 0, 0 /* endpoints */);
    mock().checkExpectations();
}

TEST(protocol_api, test_device_register_when_protocol_translator_not_registered_returns_error)
{
    struct test_context* test_ctx = protocol_translator_not_registered();

    // Build device registration jsonrpc structure
    json_t *request = json_object();
    json_object_set_new(request, "jsonrpc", json_string("2.0"));
    json_object_set_new(request, "id", json_string("1"));
    json_object_set_new(request, "method", json_string("device_register"));

    json_t *params = json_object();
    json_object_set_new(params, "deviceId", json_string("test-device"));
    json_object_set_new(request, "params", params);

    char *data = json_dumps(request, JSON_COMPACT);
    struct json_message_t *userdata = alloc_json_message_t(data, strlen(data), test_ctx->connection);
    free(data);

    json_t *result = NULL;
    mock().expectOneCall("edgeclient_is_shutting_down").andReturnValue(false);
    mock().expectOneCall("endpoint_exists").withParameter("endpoint_name", "test-device").andReturnValue(0);
    int rc = device_register(request, params, &result, userdata);
    CHECK_EQUAL(1, rc);

    CHECK(result != NULL);
    json_t *message_obj = json_object_get(result, "message");
    STRCMP_EQUAL("Protocol translator not registered.", json_string_value(message_obj));

    json_t *data_obj = json_object_get(result, "data");
    STRCMP_EQUAL("Failed to register device.", json_string_value(data_obj));

    json_decref(request);
    json_decref(result);

    deallocate_json_message_t(userdata);
    check_remove_resources_and_objects_owned_by_client(test_ctx->connection, 0 /* endpoints */);
    free_test_context(test_ctx, 0, 0, 0 /* endpoints */);
    mock().checkExpectations();
}

TEST(protocol_api, test_device_register_with_no_deviceid_returns_error)
{
    struct test_context* test_ctx = protocol_translator_registered(1);

    // Build device registration jsonrpc structure
    json_t *request = json_object();
    json_object_set_new(request, "jsonrpc", json_string("2.0"));
    json_object_set_new(request, "id", json_string("1"));
    json_object_set_new(request, "method", json_string("device_register"));

    json_t *params = json_object();
    json_object_set_new(request, "params", params);

    char *data = json_dumps(request, JSON_COMPACT);
    struct json_message_t *userdata = alloc_json_message_t(data, strlen(data), test_ctx->connection);
    free(data);

    json_t *result;
    mock().expectOneCall("edgeclient_is_shutting_down").andReturnValue(false);
    int rc = device_register(request, params, &result, userdata);
    CHECK_EQUAL(1, rc);

    CHECK(result != NULL);

    json_t *code_obj = json_object_get(result, "code");
    CHECK_EQUAL(JSONRPC_INVALID_PARAMS, (int32_t) json_integer_value(code_obj));

    json_t *message_obj = json_object_get(result, "message");
    STRCMP_EQUAL("Invalid params", json_string_value(message_obj));

    json_t *data_obj = json_object_get(result, "data");
    STRCMP_EQUAL("Missing 'deviceId' field.", json_string_value(data_obj));

    json_decref(request);
    json_decref(result);
    deallocate_json_message_t(userdata);

    check_connection_free_expectations(test_ctx->connection, 26241, 1, 0 /* endpoints */);
    free_test_context(test_ctx, 0, 0, 0 /* endpoints */);
    mock().checkExpectations();
}

TEST(protocol_api, test_device_register_with_null_deviceid_returns_error)
{
    struct test_context* test_ctx = protocol_translator_registered(1);

    // Build device registration jsonrpc structure
    json_t *request = json_object();
    json_object_set_new(request, "jsonrpc", json_string("2.0"));
    json_object_set_new(request, "id", json_string("1"));
    json_object_set_new(request, "method", json_string("device_register"));

    json_t *params = json_object();
    json_object_set_new(request, "params", params);
    json_object_set_new(params, "deviceId", json_null());

    char *data = json_dumps(request, JSON_COMPACT);
    struct json_message_t *userdata = alloc_json_message_t(data, strlen(data), test_ctx->connection);
    free(data);

    json_t *result;
    mock().expectOneCall("edgeclient_is_shutting_down").andReturnValue(false);
    int rc = device_register(request, params, &result, userdata);
    CHECK_EQUAL(1, rc);

    CHECK(result != NULL);

    json_t *code_obj = json_object_get(result, "code");
    CHECK_EQUAL(JSONRPC_INVALID_PARAMS, json_integer_value(code_obj));

    json_t *message_obj = json_object_get(result, "message");
    STRCMP_EQUAL("Invalid params", json_string_value(message_obj));

    json_t *data_obj = json_object_get(result, "data");
    STRCMP_EQUAL("Invalid 'deviceId' field value.", json_string_value(data_obj));

    json_decref(request);
    json_decref(result);
    deallocate_json_message_t(userdata);

    check_connection_free_expectations(test_ctx->connection, 26241, 1, 0 /* endpoints */);
    free_test_context(test_ctx, 0, 0, 0 /* endpoints */);
    mock().checkExpectations();
}

TEST(protocol_api, test_device_register_with_empty_deviceid_returns_error)
{
    struct test_context* test_ctx = protocol_translator_registered(1);

    // Build device registration jsonrpc structure
    json_t *request = json_object();
    json_object_set_new(request, "jsonrpc", json_string("2.0"));
    json_object_set_new(request, "id", json_string("1"));
    json_object_set_new(request, "method", json_string("device_register"));

    json_t *params = json_object();
    json_object_set_new(request, "params", params);
    json_object_set_new(params, "deviceId", json_string(""));

    char *data = json_dumps(request, JSON_COMPACT);
    struct json_message_t *userdata = alloc_json_message_t(data, strlen(data), test_ctx->connection);
    free(data);

    json_t *result;
    mock().expectOneCall("edgeclient_is_shutting_down").andReturnValue(false);
    int rc = device_register(request, params, &result, userdata);
    CHECK_EQUAL(1, rc);

    CHECK(result != NULL);

    json_t *code_obj = json_object_get(result, "code");
    CHECK_EQUAL((int32_t) JSONRPC_INVALID_PARAMS, (int32_t) json_integer_value(code_obj));

    json_t *message_obj = json_object_get(result, "message");
    STRCMP_EQUAL("Invalid params", json_string_value(message_obj));

    json_t *data_obj = json_object_get(result, "data");
    STRCMP_EQUAL("Invalid 'deviceId' field value.", json_string_value(data_obj));

    json_decref(request);
    json_decref(result);
    deallocate_json_message_t(userdata);

    check_connection_free_expectations(test_ctx->connection, 26241, 1, 0 /* endpoints */);
    free_test_context(test_ctx, 0, 0, 0 /* endpoints */);
    mock().checkExpectations();
}

TEST(protocol_api, test_device_unregister_with_null_deviceid_returns_error)
{
    struct test_context* test_ctx = protocol_translator_registered(1);

    // Build device registration jsonrpc structure
    json_t *request = json_object();
    json_object_set_new(request, "jsonrpc", json_string("2.0"));
    json_object_set_new(request, "id", json_string("1"));
    json_object_set_new(request, "method", json_string("device_unregister"));

    json_t *params = json_object();
    json_object_set_new(request, "params", params);
    json_object_set_new(params, "deviceId", json_null());

    char *data = json_dumps(request, JSON_COMPACT);
    struct json_message_t *userdata = alloc_json_message_t(data, strlen(data), test_ctx->connection);
    free(data);

    json_t *result;
    mock().expectOneCall("edgeclient_is_shutting_down").andReturnValue(false);
    int32_t old_count = edgeserver_get_number_registered_endpoints_count();
    int rc = device_unregister(request, params, &result, userdata);
    int32_t new_count = edgeserver_get_number_registered_endpoints_count();
    CHECK(new_count == old_count);
    CHECK_EQUAL(1, rc);

    CHECK(result != NULL);

    json_t *code_obj = json_object_get(result, "code");
    CHECK_EQUAL(JSONRPC_INVALID_PARAMS, json_integer_value(code_obj));

    json_t *message_obj = json_object_get(result, "message");
    STRCMP_EQUAL("Invalid params", json_string_value(message_obj));

    json_t *data_obj = json_object_get(result, "data");
    STRCMP_EQUAL("Invalid 'deviceId' field value.", json_string_value(data_obj));

    json_decref(request);
    json_decref(result);
    deallocate_json_message_t(userdata);

    check_connection_free_expectations(test_ctx->connection, 26241, 1, 0 /* endpoints */);
    free_test_context(test_ctx, 0, 0, 0 /* endpoints */);
    mock().checkExpectations();
}

TEST(protocol_api, test_device_unregister_with_empty_deviceid_returns_error)
{
    struct test_context* test_ctx = protocol_translator_registered(1);

    // Build device registration jsonrpc structure
    json_t *request = json_object();
    json_object_set_new(request, "jsonrpc", json_string("2.0"));
    json_object_set_new(request, "id", json_string("1"));
    json_object_set_new(request, "method", json_string("device_register"));

    json_t *params = json_object();
    json_object_set_new(request, "params", params);
    json_object_set_new(params, "deviceId", json_string(""));

    char *data = json_dumps(request, JSON_COMPACT);
    struct json_message_t *userdata = alloc_json_message_t(data, strlen(data), test_ctx->connection);
    free(data);

    json_t *result;
    mock().expectOneCall("edgeclient_is_shutting_down").andReturnValue(false);
    int rc = device_unregister(request, params, &result, userdata);
    CHECK_EQUAL(1, rc);

    CHECK(result != NULL);

    json_t *code_obj = json_object_get(result, "code");
    CHECK_EQUAL(JSONRPC_INVALID_PARAMS, json_integer_value(code_obj));

    json_t *message_obj = json_object_get(result, "message");
    STRCMP_EQUAL("Invalid params", json_string_value(message_obj));

    json_t *data_obj = json_object_get(result, "data");
    STRCMP_EQUAL("Invalid 'deviceId' field value.", json_string_value(data_obj));

    json_decref(request);
    json_decref(result);
    deallocate_json_message_t(userdata);

    check_connection_free_expectations(test_ctx->connection, 26241, 1, 0 /* endpoints */);
    free_test_context(test_ctx, 0, 0, 0 /* endpoints */);
    mock().checkExpectations();
}

TEST(protocol_api, test_device_unregister_when_protocol_translator_not_registered_returns_error)
{
    struct test_context* test_ctx = protocol_translator_not_registered();

    // Build device registration jsonrpc structure
    json_t *request = json_object();
    json_object_set_new(request, "jsonrpc", json_string("2.0"));
    json_object_set_new(request, "id", json_string("1"));
    json_object_set_new(request, "method", json_string("device_unregister"));

    char *data = json_dumps(request, JSON_COMPACT);
    struct json_message_t *userdata = alloc_json_message_t(data, strlen(data), test_ctx->connection);
    free(data);

    json_t *result=NULL;
    mock().expectOneCall("edgeclient_is_shutting_down").andReturnValue(false);
    int rc = device_unregister(request, NULL, &result, userdata);
    CHECK_EQUAL(1, rc);

    CHECK(result != NULL);
    json_t *message_obj = json_object_get(result, "message");
    STRCMP_EQUAL("Protocol translator not registered.", json_string_value(message_obj));
    json_t *data_obj = json_object_get(result, "data");
    STRCMP_EQUAL("Failed to unregister device.", json_string_value(data_obj));

    json_decref(request);
    json_decref(result);

    mock().expectOneCall("remove_resources_owned_by_client")
            .withPointerParameter("client_context", (void *)(test_ctx->connection));

    mock().expectOneCall("remove_objects_owned_by_client")
            .withPointerParameter("client_context", (void *)(test_ctx->connection));

    deallocate_json_message_t(userdata);
    free_test_context(test_ctx, 0, 0, 0 /* endpoints */);
    mock().checkExpectations();
}

static ValuePointer *check_unregisters_endpoint_expectations(struct connection *connection,
                                                             struct pt_device_count_expectations *dce)
{
    // Set expected set_resource_value calls
    mock().expectOneCall("edgeclient_is_shutting_down").andReturnValue(false);
    /* Check for pending requests */
    mock().expectOneCall("endpoint_exists").withStringParameter("endpoint_name", "test-device").andReturnValue(1);
    mock().expectOneCall("edge_mutex_lock").withPointerParameter("mutex", (void *) &rpc_mutex).andReturnValue(0);
    mock().expectOneCall("edge_mutex_unlock").withPointerParameter("mutex", (void *) &rpc_mutex).andReturnValue(0);
    mock().expectOneCall("remove_endpoint")
            .withParameter("endpoint_name", "test-device")
            .andReturnValue(true);
    mock().expectOneCall("get_resource_value")
            .withStringParameter("endpoint_name", NULL)
            .withParameter("object_id", PROTOCOL_TRANSLATOR_OBJECT_ID)
            .withParameter("object_instance_id", 0)
            .withParameter("resource_id", PROTOCOL_TRANSLATOR_OBJECT_COUNT_RESOURCE_ID)
            .withOutputParameterReturning("value", &dce->get_resource_value, sizeof(char*))
            .withOutputParameterReturning("value_length", dce->get_value_size, sizeof(uint32_t));

    ValuePointer *value_pointer = new ValuePointer((uint8_t*) dce->set_resource_value, *dce->set_value_size);

    mock().expectOneCall("set_resource_value")
            .withStringParameter("endpoint_name", NULL)
            .withParameter("object_id", PROTOCOL_TRANSLATOR_OBJECT_ID)
            .withParameter("object_instance_id", 0)
            .withParameter("resource_id", PROTOCOL_TRANSLATOR_OBJECT_COUNT_RESOURCE_ID)
            .withParameterOfType("ValuePointer", "value", value_pointer)
            .withParameter("value_length", sizeof(int16_t))
            .withParameter("resource_type", LWM2M_INTEGER)
            .withParameter("opr", OPERATION_READ)
            .withPointerParameter("ctx", connection)
            .andReturnValue(PT_API_SUCCESS);

    mock().expectOneCall("update_register_client_conditional");

    return value_pointer;

}

static void check_unregisters_endpoint_fails_expectations(
    struct connection *connection,
    const char *remove_endpoint_device_name)
{
    // Set expected set_resource_value calls
    mock().expectOneCall("edgeclient_is_shutting_down").andReturnValue(false);
    mock().expectOneCall("endpoint_exists")
            .withStringParameter("endpoint_name", remove_endpoint_device_name)
            .andReturnValue(0);
}

TEST(protocol_api, test_unregisters_endpoint_missing_device_id)
{
    struct test_context* test_ctx = protocol_translator_registered(0);

    struct pt_device_count_expectations *dce_register = pt_create_device_count_expectations("0", 1);
    json_t *result;
    int return_code;

    ValuePointer* pt_resource_vp = check_creates_endpoint_expectations(test_ctx->connection, dce_register);
    struct json_message_t *userdata = create_endpoint(test_ctx->connection, TEST_DEVICE_REGISTER_JSON);
    mock().expectOneCall("edgeclient_is_shutting_down").andReturnValue(false);
    json_message_t* json_message = unregister_endpoint(test_ctx->connection, NULL, &return_code, &result);
    json_t *data_obj = json_object_get(result, "data");
    STRCMP_EQUAL("Missing 'deviceId' field.", json_string_value(data_obj));
    json_decref(result);

    deallocate_json_message_t(userdata);
    deallocate_json_message_t(json_message);

    delete pt_resource_vp;
    free_pt_device_count_expectations(dce_register);

    check_connection_free_expectations(test_ctx->connection, 26241, 0, 1 /* endpoints */);
    free_test_context(test_ctx, 0 /* registered_translators */, 0 /* not_accepted_translators */, 1 /* endpoints */);
    mock().checkExpectations();
}

TEST(protocol_api, test_unregisters_existing_endpoint)
{
    struct test_context* test_ctx = protocol_translator_registered(0);

    struct pt_device_count_expectations *dce_register = pt_create_device_count_expectations("0", 1);
    struct pt_device_count_expectations *dce_unregister = pt_create_device_count_expectations("1", 0);
    json_t *result;
    int return_code;

    ValuePointer* pt_resource_vp = check_creates_endpoint_expectations(test_ctx->connection, dce_register);

    struct json_message_t *userdata = create_endpoint(test_ctx->connection, TEST_DEVICE_REGISTER_JSON);
    ValuePointer* pt_resource_vp_unreg = check_unregisters_endpoint_expectations(test_ctx->connection, dce_unregister);

    int32_t old_count = edgeserver_get_number_registered_endpoints_count();
    json_message_t *json_message = unregister_endpoint(test_ctx->connection,
                                                       TEST_DEVICE_UNREGISTER_JSON,
                                                       &return_code,
                                                       &result);
    CHECK_EQUAL(0, return_code);
    int32_t new_count = edgeserver_get_number_registered_endpoints_count();
    CHECK(new_count == old_count - 1);
    STRCMP_EQUAL("ok", json_string_value(result));
    json_decref(result);

    deallocate_json_message_t(userdata);
    deallocate_json_message_t(json_message);

    delete pt_resource_vp;
    delete pt_resource_vp_unreg;
    free_pt_device_count_expectations(dce_register);
    free_pt_device_count_expectations(dce_unregister);

    check_connection_free_expectations(test_ctx->connection, 26241, 0, 0 /* endpoints */);
    free_test_context(test_ctx, 0 /* registered_translators */, 0 /* not_accepted_translators */, 0 /* endpoints */);
    mock().checkExpectations();
}

TEST(protocol_api, test_unregisters_existing_endpoint_twice)
{
    struct test_context* test_ctx = protocol_translator_registered(0);

    struct pt_device_count_expectations *dce_register = pt_create_device_count_expectations("0", 1);
    struct pt_device_count_expectations *dce_unregister = pt_create_device_count_expectations("1", 0);
    json_t *result;
    int return_code;

    ValuePointer* pt_resource_vp = check_creates_endpoint_expectations(test_ctx->connection, dce_register);

    struct json_message_t *userdata = create_endpoint(test_ctx->connection, TEST_DEVICE_REGISTER_JSON);

    ValuePointer* pt_resource_vp_unreg = check_unregisters_endpoint_expectations(test_ctx->connection, dce_unregister);
    json_message_t *json_message = unregister_endpoint(test_ctx->connection,
                                                       TEST_DEVICE_UNREGISTER_JSON,
                                                       &return_code,
                                                       &result);
    CHECK_EQUAL(0, return_code);
    STRCMP_EQUAL("ok", json_string_value(result));
    json_decref(result);
    deallocate_json_message_t(json_message);
    check_unregisters_endpoint_fails_expectations(test_ctx->connection, "test-device");

    json_message = unregister_endpoint(test_ctx->connection, TEST_DEVICE_UNREGISTER_JSON, &return_code, &result);
    CHECK(return_code == 1);
    json_t *data_obj = json_object_get(result, "data");
    json_t *code_obj = json_object_get(result, "code");
    STRCMP_EQUAL("Endpoint was not found.", json_string_value(data_obj));
    CHECK_EQUAL(PT_API_RESOURCE_NOT_FOUND, json_integer_value(code_obj));
    json_decref(result);

    deallocate_json_message_t(json_message);
    deallocate_json_message_t(userdata);

    delete pt_resource_vp;
    delete pt_resource_vp_unreg;
    free_pt_device_count_expectations(dce_register);
    free_pt_device_count_expectations(dce_unregister);

    check_connection_free_expectations(test_ctx->connection, 26241, 0, 0 /* endpoints */);
    free_test_context(test_ctx, 0 /* registered_translators */, 0 /* not_accepted_translators */, 0 /* endpoints */);
    mock().checkExpectations();
}

TEST(protocol_api, test_unregisters_non_existing_endpoint)
{
    struct test_context* test_ctx = protocol_translator_registered(0);

    struct pt_device_count_expectations *dce_register = pt_create_device_count_expectations("0", 1);
    json_t *result;
    int return_code;

    ValuePointer* pt_resource_vp = check_creates_endpoint_expectations(test_ctx->connection, dce_register);

    struct json_message_t *userdata = create_endpoint(test_ctx->connection, TEST_DEVICE_REGISTER_JSON);

    check_unregisters_endpoint_fails_expectations(test_ctx->connection, "test-device-2");
    json_message_t *json_message = unregister_endpoint(test_ctx->connection,
                                                       TEST_DEVICE2_UNREGISTER_JSON,
                                                       &return_code,
                                                       &result);
    CHECK(return_code == 1);
    json_t *data_obj = json_object_get(result, "data");
    STRCMP_EQUAL("Endpoint was not found.", json_string_value(data_obj));
    json_t *message_obj = json_object_get(result, "message");
    STRCMP_EQUAL("Resource not found.", json_string_value(message_obj));
    json_t *code_obj = json_object_get(result, "code");
    CHECK_EQUAL(PT_API_RESOURCE_NOT_FOUND, json_integer_value(code_obj));

    json_decref(result);

    deallocate_json_message_t(userdata);
    deallocate_json_message_t(json_message);

    delete pt_resource_vp;
    free_pt_device_count_expectations(dce_register);

    check_connection_free_expectations(test_ctx->connection, 26241, 0, 1 /* endpoints */);
    free_test_context(test_ctx, 0 /* registered_translators */, 0 /* not_accepted_translators */, 1 /* endpoints */);
    mock().checkExpectations();
}

static int free_all_translators(connection_elem_list *translators)
{
    int count = 0;
    ns_list_foreach_safe(struct connection_list_elem, cur, translators) {
        ns_list_remove(translators, cur);
        free(cur);
        count++;
    }
    return count;
}

TEST(protocol_api, test_write_value_success)
{
    struct test_context* test_ctx = protocol_translator_registered(0);

    // Load device registration jsonrpc parameters structure from file
    json_t *params = load_json_params(TEST_DEVICE_REGISTER_JSON);

    // Build device registration jsonrpc structure
    json_t *request = json_object();
    json_object_set_new(request, "jsonrpc", json_string("2.0"));
    json_object_set_new(request, "id", json_string("1"));
    json_object_set_new(request, "method", json_string("write"));
    json_object_set_new(request, "params", params);

    mock().expectOneCall("edgeclient_is_shutting_down").andReturnValue(false);
    char *data = json_dumps(request, JSON_COMPACT);
    struct json_message_t *userdata = alloc_json_message_t(data, strlen(data), test_ctx->connection);
    free(data);

    mock().expectNCalls(2, "endpoint_exists")
            .withParameter("endpoint_name", "test-device")
            .andReturnValue(1);

    expected_device_register_test_structure(test_ctx->connection);

    mock().expectOneCall("update_register_client_conditional");

    json_t *result;
    int rc = write_value(request, params, &result, userdata);
    CHECK_EQUAL(0, rc);

    CHECK(result != NULL);
    STRCMP_EQUAL("ok", json_string_value(result));

    json_decref(request);
    json_decref(result);

    check_connection_free_expectations(test_ctx->connection, 26241, 0, 0 /* endpoints */);
    deallocate_json_message_t(userdata);

    free_test_context(test_ctx, 0 /* registered_translators*/, 0 /* not_accepted_translators */, 0 /* endpoints */);
    mock().checkExpectations();
}

TEST(protocol_api, test_write_value_failure)
{
    struct test_context* test_ctx = protocol_translator_registered(0);

    // Load device registration jsonrpc parameters structure from file
    json_t *params = load_json_params(TEST_WRITE_VALUE_FAILURE_JSON);

    // Build device registration jsonrpc structure
    json_t *request = json_object();
    json_object_set_new(request, "jsonrpc", json_string("2.0"));
    json_object_set_new(request, "id", json_string("1"));
    json_object_set_new(request, "method", json_string("write"));
    json_object_set_new(request, "params", params);

    mock().expectOneCall("edgeclient_is_shutting_down").andReturnValue(false);
    char *data = json_dumps(request, JSON_COMPACT);
    struct json_message_t *userdata = alloc_json_message_t(data, strlen(data), test_ctx->connection);
    free(data);

    mock().expectNCalls(2, "endpoint_exists")
            .withParameter("endpoint_name", "test-device")
            .andReturnValue(1);

    ValuePointer int_value_pointer = ValuePointer((uint8_t*) "100", strlen("100"));
    mock().expectOneCall("edgeclient_verify_value")
            .withParameterOfType("ValuePointer", "value", (const void *) &int_value_pointer)
            .withParameter("value_length", strlen("100"))
            .withParameter("resource_type", LWM2M_INTEGER)
            .andReturnValue(true);
    mock().expectOneCall("set_resource_value")
            .withStringParameter("endpoint_name", "test-device")
            .withParameter("object_id", 22)
            .withParameter("object_instance_id", 0)
            .withParameter("resource_id", 37)
            .withParameterOfType("ValuePointer", "value", (const void *) &int_value_pointer)
            .withParameter("value_length", strlen("100"))
            .withParameter("resource_type", LWM2M_INTEGER)
            .withParameter("opr", OPERATION_READ)
            .withPointerParameter("ctx", test_ctx->connection)
            .andReturnValue(PT_API_ILLEGAL_VALUE);

    mock().expectOneCall("update_register_client_conditional");

    json_t *result;
    int rc = write_value(request, params, &result, userdata);
    CHECK_EQUAL(1, rc);

    CHECK(result != NULL);

    json_t *message_obj = json_object_get(result, "message");
    STRCMP_EQUAL("Illegal value.", json_string_value(message_obj));

    json_decref(request);
    json_decref(result);

    check_connection_free_expectations(test_ctx->connection, 26241, 0, 0 /* endpoints */);
    deallocate_json_message_t(userdata);

    free_test_context(test_ctx, 0 /* registered_translators*/, 0 /* not_accepted_translators */, 0 /* endpoints */);
    mock().checkExpectations();
}


TEST(protocol_api, test_write_value_failure_when_endpoint_limit_reached)
{
    struct test_context* test_ctx = protocol_translator_registered(0);

    // Set endpoint limit to 1
    edgeserver_set_number_registered_endpoints_limit(5);
    edgeserver_change_number_registered_endpoints_by_delta(5);

    // Load device registration jsonrpc parameters structure from file
    json_t *params = load_json_params(TEST_WRITE_VALUE_FAILURE_JSON);

    // Build device registration jsonrpc structure
    json_t *request = json_object();
    json_object_set_new(request, "jsonrpc", json_string("2.0"));
    json_object_set_new(request, "id", json_string("2"));
    json_object_set_new(request, "method", json_string("write"));
    json_object_set_new(request, "params", params);

    mock().expectOneCall("edgeclient_is_shutting_down").andReturnValue(false);
    char *data = json_dumps(request, JSON_COMPACT);
    struct json_message_t *userdata = alloc_json_message_t(data, strlen(data), test_ctx->connection);
    free(data);

    mock().expectOneCall("endpoint_exists")
            .withParameter("endpoint_name", "test-device")
            .andReturnValue(0);

    json_t *result;
    int rc = write_value(request, params, &result, userdata);
    CHECK_EQUAL(1, rc);

    CHECK(result != NULL);

    json_t *message_obj = json_object_get(result, "message");
    STRCMP_EQUAL("The maximum number of registered endpoints is already in use.", json_string_value(message_obj));

    json_decref(request);
    json_decref(result);

    edgeserver_change_number_registered_endpoints_by_delta(-5);

    check_connection_free_expectations(test_ctx->connection, 26241, 0, 0 /* endpoints */);
    deallocate_json_message_t(userdata);

    free_test_context(test_ctx, 0 /* registered_translators*/, 0 /* not_accepted_translators */, 0 /* endpoints */);
    mock().checkExpectations();
}

TEST(protocol_api, test_write_value_fails_when_creating_endpoint_fails)
{
    struct test_context* test_ctx = protocol_translator_registered(0);

    // Load device registration jsonrpc parameters structure from file
    json_t *params = load_json_params(TEST_DEVICE_REGISTER_JSON);

    // Build device registration jsonrpc structure
    json_t *request = json_object();
    json_object_set_new(request, "jsonrpc", json_string("2.0"));
    json_object_set_new(request, "id", json_string("1"));
    json_object_set_new(request, "method", json_string("write"));
    json_object_set_new(request, "params", params);

    char *data = json_dumps(request, JSON_COMPACT);
    struct json_message_t *userdata = alloc_json_message_t(data, strlen(data), test_ctx->connection);
    free(data);

    mock().expectOneCall("edgeclient_is_shutting_down").andReturnValue(false);
    mock().expectNCalls(2, "endpoint_exists")
            .withParameter("endpoint_name", "test-device")
            .andReturnValue(0);

    mock().expectOneCall("add_endpoint")
        .withParameter("endpoint_name", "test-device")
        .withParameter("ctx", test_ctx->connection)
        .andReturnValue(0);

    json_t *result = NULL;
    int rc = write_value(request, params, &result, userdata);
    CHECK_EQUAL(1, rc);

    CHECK(result != NULL);
    json_t *data_obj = json_object_get(result, "data");
    STRCMP_EQUAL("Write value failed. Failed to update device values from json.", json_string_value(data_obj));
    json_t *message_obj = json_object_get(result, "message");
    STRCMP_EQUAL("Protocol translator API internal error.", json_string_value(message_obj));

    json_decref(request);
    json_decref(result);

    check_connection_free_expectations(test_ctx->connection, 26241, 0, 0 /* endpoints */);
    deallocate_json_message_t(userdata);

    free_test_context(test_ctx, 0 /* registered_translators*/, 0 /* not_accepted_translators */, 0 /* endpoints */);
    mock().checkExpectations();
}

TEST(protocol_api, test_write_value_fails_when_deviceid_is_missing_from_params)
{
    struct test_context* test_ctx = protocol_translator_registered(0);

    // use empty params
    json_t *params = json_object();

    // Build device registration jsonrpc structure
    json_t *request = json_object();
    json_object_set_new(request, "jsonrpc", json_string("2.0"));
    json_object_set_new(request, "id", json_string("1"));
    json_object_set_new(request, "method", json_string("write"));
    json_object_set_new(request, "params", params);

    char *data = json_dumps(request, JSON_COMPACT);
    struct json_message_t *userdata = alloc_json_message_t(data, strlen(data), test_ctx->connection);
    free(data);

    json_t *result = NULL;
    mock().expectOneCall("edgeclient_is_shutting_down").andReturnValue(false);
    int rc = write_value(request, params, &result, userdata);
    CHECK_EQUAL(1, rc);

    CHECK(result != NULL);
    json_t *data_obj = json_object_get(result, "data");
    STRCMP_EQUAL("Missing 'deviceId' field.", json_string_value(data_obj));

    json_decref(request);
    json_decref(result);

    check_connection_free_expectations(test_ctx->connection, 26241, 0, 0 /* endpoints */);
    deallocate_json_message_t(userdata);

    free_test_context(test_ctx, 0 /* registered_translators*/, 0 /* not_accepted_translators */, 0 /* endpoints */);
    mock().checkExpectations();
}

TEST(protocol_api, test_write_value_fails_when_requestid_is_not_provided)
{
    struct test_context* test_ctx = protocol_translator_registered(0);

    // Load device registration jsonrpc parameters structure from file
    json_t *params = load_json_params(TEST_DEVICE_REGISTER_JSON);

    // Build device registration jsonrpc structure
    json_t *request = json_object();
    json_object_set_new(request, "jsonrpc", json_string("2.0"));
    json_object_set_new(request, "method", json_string("write"));
    json_object_set_new(request, "params", params);

    char *data = json_dumps(request, JSON_COMPACT);
    struct json_message_t *userdata = alloc_json_message_t(data, strlen(data), test_ctx->connection);
    free(data);

    json_t *result = NULL;
    mock().expectOneCall("edgeclient_is_shutting_down").andReturnValue(false);
    int rc = write_value(request, params, &result, userdata);
    CHECK_EQUAL(1, rc);

    CHECK(result != NULL);
    json_t *data_obj = json_object_get(result, "data");
    STRCMP_EQUAL("Write value failed. No request id was given.", json_string_value(data_obj));

    json_decref(request);
    json_decref(result);

    check_connection_free_expectations(test_ctx->connection, 26241, 0, 0 /* endpoints */);

    deallocate_json_message_t(userdata);

    free_test_context(test_ctx, 0 /* registered_translators*/, 0 /* not_accepted_translators */, 0 /* endpoints */);
    mock().checkExpectations();
}

TEST(protocol_api, test_write_value_fails_when_non_string_value)
{
    struct test_context* test_ctx = protocol_translator_registered(0);

    // Load device registration jsonrpc parameters structure from file
    json_t *params = load_json_params(TEST_WRITE_NON_STRING_VALUE_JSON);

    // Build device registration jsonrpc structure
    json_t *request = json_object();
    json_object_set_new(request, "jsonrpc", json_string("2.0"));
    json_object_set_new(request, "id", json_string("1"));
    json_object_set_new(request, "method", json_string("write"));
    json_object_set_new(request, "params", params);

    char *data = json_dumps(request, JSON_COMPACT);
    struct json_message_t *userdata = alloc_json_message_t(data, strlen(data), test_ctx->connection);
    free(data);

    json_t *result = NULL;

    mock().expectNCalls(2, "endpoint_exists")
            .withParameter("endpoint_name", "test-device")
            .andReturnValue(0);

    mock().expectOneCall("add_endpoint")
        .withParameter("endpoint_name", "test-device")
        .withParameter("ctx", test_ctx->connection)
        .andReturnValue(0);
    mock().expectOneCall("edgeclient_is_shutting_down").andReturnValue(false);
    int rc = write_value(request, params, &result, userdata);
    CHECK_EQUAL(1, rc);

    CHECK(result != NULL);
    json_t *data_obj = json_object_get(result, "data");
    STRCMP_EQUAL("Write value failed. Failed to update device values from json.", json_string_value(data_obj));

    json_decref(request);
    json_decref(result);

    check_connection_free_expectations(test_ctx->connection, 26241, 0, 0 /* endpoints */);

    deallocate_json_message_t(userdata);

    free_test_context(test_ctx, 0 /* registered_translators*/, 0 /* not_accepted_translators */, 0 /* endpoints */);
    mock().checkExpectations();
}

TEST(protocol_api, test_write_value_fails_when_protocoltranslator_not_registered)
{
    struct test_context* test_ctx = protocol_translator_not_registered();

    // Load device registration jsonrpc parameters structure from file
    json_t *params = load_json_params(TEST_DEVICE_REGISTER_JSON);

    // Build device registration jsonrpc structure
    json_t *request = json_object();
    json_object_set_new(request, "jsonrpc", json_string("2.0"));
    json_object_set_new(request, "id", json_string("1"));
    json_object_set_new(request, "method", json_string("write"));
    json_object_set_new(request, "params", params);

    char *data = json_dumps(request, JSON_COMPACT);
    struct json_message_t *userdata = alloc_json_message_t(data, strlen(data), test_ctx->connection);
    free(data);

    json_t *result;
    mock().expectOneCall("edgeclient_is_shutting_down").andReturnValue(false);
    int rc = write_value(request, params, &result, userdata);
    CHECK_EQUAL(1, rc);

    CHECK(result != NULL);
    json_t *data_obj = json_object_get(result, "data");
    STRCMP_EQUAL("Write value failed. Protocol translator not registered.", json_string_value(data_obj));

    json_decref(request);
    json_decref(result);
    deallocate_json_message_t(userdata);

    check_remove_resources_and_objects_owned_by_client(test_ctx->connection, 0 /* endpoints */);
    free_test_context(test_ctx, 0 /* registered_translators*/, 0 /* not_accepted_translators */, 0 /* endpoints */);
    mock().checkExpectations();
}

static void alloc_multiple_devices_test_data(multiple_devices_test_data_t *data,
                                                                      int32_t num_devices)
{
    data->pt_device_amount_read = (char **) malloc(sizeof(char *) * num_devices);
    data->pt_device_amount_set = (int16_t **)malloc(sizeof(uint16_t *) * num_devices);
    data->value_pointers = (ValuePointer **)malloc(sizeof(ValuePointer *) * num_devices);
    data->num_devices = num_devices;
    int32_t i;
    for (i = 0; i < num_devices; i++) {
        data->pt_device_amount_set[i] = (int16_t *) calloc(1, sizeof(uint16_t));
    }
}

static void free_multiple_devices_test_data(multiple_devices_test_data_t *data)
{
    int32_t i;
    for (i = 0; i < data->num_devices; i++) {
        // pt_device_amount_read is freed in the protocol_api.c implementation
        free(data->pt_device_amount_set[i]);
        delete data->value_pointers[i];
    }
    free(data->pt_device_amount_read);
    free(data->pt_device_amount_set);
    free(data->value_pointers);
}

TEST(protocol_api, test_multiple_device_registration)
{
    struct test_context* test_ctx = protocol_translator_registered(0);
    multiple_devices_test_data_t data;
    alloc_multiple_devices_test_data(&data, 10);
    int32_t i = 0;
    for (i = 0; i < data.num_devices; i++) {
        int16_t cur_num = i + 10;
        size_t buffer_len = integer_to_text_format(cur_num, NULL, 0) + 1;
        data.pt_device_amount_read[i] = (char*) calloc(buffer_len, sizeof(char));;
        integer_to_text_format(cur_num, data.pt_device_amount_read[i], buffer_len);
        *(data.pt_device_amount_set[i]) = htons(i + 11);
    }
    for (i = 0; i < data.num_devices; i++) {
        register_device_with_index(&data, test_ctx, i, i, PT_API_SUCCESS);
    }
    CHECK_EQUAL(data.num_devices, edgeserver_get_number_registered_endpoints_count());
    free_multiple_devices_test_data(&data);
    check_connection_free_expectations(test_ctx->connection, 26241, 0, 10 /* endpoints */);
    free_test_context(test_ctx, 0 /* registered_translators*/, 0 /* not_accepted_translators */, 10 /* endpoints */);
    CHECK_EQUAL(0, edgeserver_get_number_registered_endpoints_count());
    mock().checkExpectations();
}

TEST(protocol_api, test_write_to_pt_null)
{
    struct test_context *test_ctx = connection_initialized();

    CHECK_EQUAL(1, write_to_pt(NULL, test_ctx->context));

    check_remove_resources_and_objects_owned_by_client(test_ctx->connection, 0 /* endpoints */);
    free_test_context(test_ctx, 0 /* registered_translators*/, 0 /* not_accepted_translators */, 0 /* endpoints */);
    mock().checkExpectations();
}

static void test_uri_common(const char *uri, int expected_return_value)
{
    int32_t uri_len = strlen(uri);
    int32_t uri_size = uri_len + 1;
    struct ctx_data *ctx_data = (struct ctx_data *) g_program_context->ctx_data;
    ns_list_init(&ctx_data->registered_translators);
    struct test_context *test_ctx = create_test_context(g_program_context);
    mock().expectOneCall("lws_hdr_total_length")
            .withIntParameter("h", (int) WSI_TOKEN_GET_URI)
            .andReturnValue((int) uri_len);
    mock().expectOneCall("lws_hdr_copy")
            .withIntParameter("len", (int) uri_size)
            .withIntParameter("h", (int) WSI_TOKEN_GET_URI)
            .withOutputParameterReturning("dest", uri, uri_size)
            .andReturnValue(0);

    CHECK(expected_return_value == server_test_connection_filter_cb(uri));
    free_test_context(test_ctx, 0 /* registered_translators*/, 0 /* not_accepted_translators */, 0 /* endpoints */);
}

TEST(protocol_api, test_accept_connection_when_version_uri_is_correct)
{
    test_uri_common("/1/pt", 0);
    mock().checkExpectations();
}

TEST(protocol_api, test_reject_connection_when_version_uri_is_incorrect)
{
    test_uri_common("/a/pt", -1);
    mock().checkExpectations();
}

TEST(protocol_api, test_write_to_pt_value_len_0)
{
    struct test_context *test_ctx = connection_initialized();
    struct connection *connection = test_ctx->connection;

    // Use a empty string as a value
    uint8_t *value = (uint8_t *) "";
    const uint32_t value_len = 0;

    edgeclient_request_context_t *request_ctx = (edgeclient_request_context_t *) malloc(
            sizeof(edgeclient_request_context_t));
    request_ctx->device_id = strdup("device_name");
    request_ctx->object_id = 5432;
    request_ctx->object_instance_id = 0;
    request_ctx->resource_id = 0;
    request_ctx->operation = OPERATION_WRITE;
    request_ctx->value_len = value_len;
    request_ctx->value = value;
    request_ctx->success_handler = edgeclient_response_handler_success_test_mock;
    request_ctx->failure_handler = edgeclient_response_handler_failure_test_mock;
    request_ctx->connection = connection;

    CHECK_EQUAL(1, write_to_pt(request_ctx, test_ctx->context));

    check_remove_resources_and_objects_owned_by_client(test_ctx->connection, 0 /* endpoints */);
    free_test_context(test_ctx, 0 /* registered_translators*/, 0 /* not_accepted_translators */, 0 /* endpoints */);
    mock().checkExpectations();
    free(request_ctx->device_id);
    free(request_ctx);
}

TEST(protocol_api, test_write_to_pt_post_value_len_0)
{
    struct test_context *test_ctx = connection_initialized();
    struct connection *connection = test_ctx->connection;

    client_data_t *client_data = edge_core_create_client(PT);
    // Use a empty string as a value
    uint8_t *value = (uint8_t *) "";
    const uint32_t value_len = 0;
    MyJsonFrameComparator comparator;

    edgeclient_request_context_t *request_ctx = (edgeclient_request_context_t *) malloc(
            sizeof(edgeclient_request_context_t));
    request_ctx->device_id = strdup("device_name");
    request_ctx->object_id = 5432;
    request_ctx->object_instance_id = 0;
    request_ctx->resource_id = 0;
    request_ctx->operation = OPERATION_EXECUTE;
    request_ctx->value_len = value_len;
    request_ctx->value = value;
    request_ctx->success_handler = edgeclient_response_handler_success_test_mock;
    request_ctx->failure_handler = edgeclient_response_handler_failure_test_mock;
    request_ctx->connection = connection;
    const char *expected_data = "{\"id\":\"1\",\"jsonrpc\":\"2.0\",\"method\":\"write\",\"params\":{"
                                "\"operation\":4,\"uri\":{\"deviceId\":\"device_name\",\"objectId\":5432,\"object"
                                "InstanceId\":0,\"resourceId\":0},\"value\":\"\"}}";
    MyJsonFrame frame = MyJsonFrame(expected_data);
    mock().installComparator("MyJsonFrame", comparator);

    /* Assert that the success handler is called */
    mock().expectOneCall("edgeclient_response_success_handler").withPointerParameter("ctx", request_ctx);
    mock().expectNoCall("edgeclient_response_failure_handler");
    mock().expectOneCall("lws_callback_on_writable").andReturnValue(1);
    mock().expectOneCall("lws_write").withParameterOfType("MyJsonFrame", "buf", (const void *) &frame);
    expect_mutexing();
    expect_mutexing();
    CHECK_EQUAL(0, write_to_pt(request_ctx, connection));

    char *response = strdup("{\"id\":\"1\",\"jsonrpc\":\"2.0\",\"result\":\"ok\"}");
    bool protocol_error;
    int rc = rpc_handle_message(response,
                                strlen(response),
                                connection,
                                (jsonrpc_method_entry_t *) client_data->method_table,
                                rpc_write_func_mock,
                                &protocol_error,
                                false /* mutex_acquired */);
    CHECK_EQUAL(false, protocol_error);
    CHECK_EQUAL(0, rc);

    check_remove_resources_and_objects_owned_by_client(test_ctx->connection, 0 /* endpoints */);
    free(response);
    free_test_context(test_ctx, 0 /* registered_translators*/, 0 /* not_accepted_translators */, 0 /* endpoints */);
    free(request_ctx->device_id);
    free(request_ctx);
    edge_core_client_data_destroy(&client_data);
    mock().checkExpectations();
}

TEST(protocol_api, test_write_to_pt_empty_string)
{
    struct test_context* test_ctx = connection_initialized();
    struct connection *connection = test_ctx->connection;
    client_data_t *client_data = edge_core_create_client(PT);

    // Use a empty string as a value
    uint8_t *value = (uint8_t *) "";
    const uint32_t value_len = 1;

    const char *expected_data = "{\"id\":\"1\",\"jsonrpc\":\"2.0\",\"method\":\"write\",\"params\":{"
                                "\"operation\":2,\"uri\":{\"deviceId\":\"device_name\",\"objectId\":5432,\"object"
                                "InstanceId\":0,\"resourceId\":0},\"value\":\"AA==\"}}";

    MyJsonFrameComparator comparator;
    MyJsonFrame frame = MyJsonFrame(expected_data);
    mock().installComparator("MyJsonFrame", comparator);

    edgeclient_request_context_t *request_ctx = (edgeclient_request_context_t *) malloc(
            sizeof(edgeclient_request_context_t));
    request_ctx->device_id = strdup("device_name");
    request_ctx->object_id = 5432;
    request_ctx->object_instance_id = 0;
    request_ctx->resource_id = 0;
    request_ctx->operation = OPERATION_WRITE;
    request_ctx->value_len = value_len;
    request_ctx->value = value;
    request_ctx->success_handler = edgeclient_response_handler_success_test_mock;
    request_ctx->failure_handler = edgeclient_response_handler_failure_test_mock;
    request_ctx->connection = connection;

    /* Assert that the success handler is called */
    mock().expectOneCall("edgeclient_response_success_handler").withPointerParameter("ctx", request_ctx);
    mock().expectNoCall("edgeclient_response_failure_handler");
    mock().expectOneCall("lws_callback_on_writable").andReturnValue(1);
    mock().expectOneCall("lws_write").withParameterOfType("MyJsonFrame", "buf", (const void *) &frame);
    expect_mutexing();
    expect_mutexing();
    CHECK_EQUAL(0, write_to_pt(request_ctx, connection));

    char *response = strdup("{\"id\":\"1\",\"jsonrpc\":\"2.0\",\"result\":\"ok\"}");
    bool protocol_error;
    int rc = rpc_handle_message(response,
                                strlen(response),
                                connection,
                                (jsonrpc_method_entry_t *) client_data->method_table,
                                rpc_write_func_mock,
                                &protocol_error,
                                false /* mutex_acquired */);
    CHECK_EQUAL(false, protocol_error);
    CHECK_EQUAL(0, rc);

    check_remove_resources_and_objects_owned_by_client(test_ctx->connection, 0 /* endpoints */);
    free(response);
    free_test_context(test_ctx, 0 /* registered_translators*/, 0 /* not_accepted_translators */, 0 /* endpoints */);
    free(request_ctx->device_id);
    free(request_ctx);
    edge_core_client_data_destroy(&client_data);
    mock().checkExpectations();
}

static edgeclient_request_context_t *write_successfully(struct test_context *test_ctx)
{
    MyJsonFrame *frame;
    mock().expectOneCall("lws_hdr_total_length")
        .withIntParameter("h", (int) WSI_TOKEN_GET_URI)
        .andReturnValue((int) strlen("/1/pt"));
    mock().expectOneCall("lws_hdr_copy")
        .withOutputParameterReturning("dest", "/1/pt", strlen("/1/pt"))
        .ignoreOtherParameters()
        .andReturnValue(1);
    expect_mutexing();
    mock().expectOneCall("lws_callback_on_writable").andReturnValue(1);
    MyJsonFrameComparator comparator;
    const char *expected_data = "{\"id\":\"1\",\"method\":\"write\",\"jsonrpc\":\"2.0\",\"params\":{"
                                "\"operation\":2,\"uri\":{\"deviceId\":\"device_name\",\"objectId\":5432,\"object"
                                "InstanceId\":0,\"resourceId\":0},\"value\":\"YQ==\"}}";
    frame = new MyJsonFrame(expected_data);
    mock().installComparator("MyJsonFrame", comparator);
    mock().expectOneCall("lws_write").withParameterOfType("MyJsonFrame", "buf", (const void *) frame);

    // Use a simple 'a'-character as a value
    uint8_t value = 'a';
    const uint32_t value_len = sizeof(value);

    test_ctx->connection = server_test_establish_connection();
    struct connection *connection = test_ctx->connection;

    edgeclient_request_context_t *request_ctx =
        (edgeclient_request_context_t*) malloc(sizeof(edgeclient_request_context_t));
    request_ctx->device_id = strdup("device_name");
    request_ctx->object_id = 5432;
    request_ctx->object_instance_id = 0;
    request_ctx->resource_id = 0;
    request_ctx->operation = OPERATION_WRITE;
    request_ctx->value_len = value_len;
    request_ctx->value = &value;
    request_ctx->success_handler = edgeclient_response_handler_success_test_mock;
    request_ctx->failure_handler = edgeclient_response_handler_failure_test_mock;
    request_ctx->connection = connection;

    CHECK_EQUAL(0, write_to_pt(request_ctx, connection));
    mock().checkExpectations();
    delete frame;
    return request_ctx;
}

TEST(protocol_api, test_write_to_pt_normal)
{
    struct test_context *test_ctx = create_test_context(g_program_context);
    client_data_t *client_data = edge_core_create_client(PT);
    edgeclient_request_context_t *request_ctx = write_successfully(test_ctx);

    char *response = strdup("{\"id\":\"1\",\"jsonrpc\":\"2.0\",\"result\":\"ok\"}");
    bool protocol_error;

    /* Assert that the success handler is called */
    mock().expectOneCall("edgeclient_response_success_handler")
        .withPointerParameter("ctx", request_ctx);
    mock().expectNoCall("edgeclient_response_failure_handler");
    expect_mutexing();
    int rc = rpc_handle_message(response,
                                strlen(response),
                                test_ctx->connection,
                                (jsonrpc_method_entry_t *) client_data->method_table,
                                rpc_write_func_mock,
                                &protocol_error,
                                false /* mutex_acquired */);
    CHECK_EQUAL(false, protocol_error);
    CHECK_EQUAL(0, rc);

    check_remove_resources_and_objects_owned_by_client(test_ctx->connection, 0 /* endpoints */);
    free(response);
    free_test_context(test_ctx, 0 /* registered_translators*/, 0 /* not_accepted_translators */, 0 /* endpoints */);
    free(request_ctx->device_id);
    free(request_ctx);
    edge_core_client_data_destroy(&client_data);
    mock().checkExpectations();
}

TEST(protocol_api, test_write_to_pt_timeout_response)
{
    struct test_context *test_ctx = create_test_context(g_program_context);
    client_data_t *client_data = edge_core_create_client(PT);
    edgeclient_request_context_t *request_ctx = write_successfully(test_ctx);

    char *response = strdup("{\"id\":\"1\",\"jsonrpc\":\"2.0\",\"error\":{\"code\":-30007,\"data\":\"Request "
                            "timeout\",\"message\": \"Timeout response with timeout threshold 60000 ms\"}}");
    bool protocol_error;

    /* Assert that the success handler is called */
    mock().expectNoCall("edgeclient_response_success_handler");
    mock().expectOneCall("edgeclient_response_failure_handler").withPointerParameter("ctx", request_ctx);
    expect_mutexing();
    int rc = rpc_handle_message(response,
                                strlen(response),
                                test_ctx->connection,
                                (jsonrpc_method_entry_t *) client_data->method_table,
                                rpc_write_func_mock,
                                &protocol_error,
                                false /* mutex_acquired */);
    CHECK_EQUAL(false, protocol_error);
    CHECK_EQUAL(0, rc);
    CHECK_EQUAL(PT_API_REQUEST_TIMEOUT, request_ctx->jsonrpc_error_code);

    check_remove_resources_and_objects_owned_by_client(test_ctx->connection, 0 /* endpoints */);
    free(response);
    free_test_context(test_ctx, 0 /* registered_translators*/, 0 /* not_accepted_translators */, 0 /* endpoints */);
    free(request_ctx->device_id);
    free(request_ctx);
    edge_core_client_data_destroy(&client_data);
    mock().checkExpectations();
}

TEST(protocol_api, test_write_to_pt_fails_when_value_is_null)
{
    struct test_context* test_ctx = connection_initialized();

    mock().expectNoCall("mbedtls_base64_encode");

    MyJsonFrameComparator comparator;
    mock().installComparator("MyJsonFrame", comparator);
    struct connection *connection = test_ctx->connection;

    edgeclient_request_context_t *request_ctx =
        (edgeclient_request_context_t*) malloc(sizeof(edgeclient_request_context_t));
    request_ctx->device_id = strdup("device_name");
    request_ctx->object_id = 5432;
    request_ctx->object_instance_id = 0;
    request_ctx->resource_id = 0;
    request_ctx->operation = OPERATION_WRITE;
    request_ctx->value_len = 0;
    request_ctx->value = NULL;
    request_ctx->success_handler = edgeclient_response_handler_success_test_mock;
    request_ctx->failure_handler = edgeclient_response_handler_failure_test_mock;
    request_ctx->connection = connection;

    /* Assert that the success or failure handler is not called */
    mock().expectNoCall("edgeclient_response_failure_handler");
    mock().expectNoCall("edgeclient_response_success_handler");

    CHECK_EQUAL(1, write_to_pt(request_ctx, test_ctx->context));

    check_remove_resources_and_objects_owned_by_client(test_ctx->connection, 0 /* endpoints */);
    free_test_context(test_ctx, 0 /* registered_translators*/, 0 /* not_accepted_translators */, 0 /* endpoints */);
    free(request_ctx->device_id);
    free(request_ctx);
    mock().checkExpectations();
}

TEST(protocol_api, test_write_to_pt_fails_when_device_id_is_null)
{
    struct test_context *test_ctx = connection_initialized();

    mock().expectNoCall("mbedtls_base64_encode");

    MyJsonFrameComparator comparator;
    mock().installComparator("MyJsonFrame", comparator);

    /* Assert that the success and failure handler is not called */
    mock().expectNoCall("edgeclient_response_success_handler");
    mock().expectNoCall("edgeclient_response_failure_handler");

    edgeclient_request_context_t *request_ctx =
        (edgeclient_request_context_t*) malloc(sizeof(edgeclient_request_context_t));
    request_ctx->device_id = NULL;

    CHECK_EQUAL(1, write_to_pt(request_ctx, test_ctx->context));

    check_remove_resources_and_objects_owned_by_client(test_ctx->connection, 0 /* endpoints */);
    free_test_context(test_ctx, 0 /* registered_translators*/, 0 /* not_accepted_translators */, 0 /* endpoints */);
    free(request_ctx);
    mock().checkExpectations();
}

TEST(protocol_api, test_edge_common_read_cb_data_frame)
{
    struct test_context *test_ctx = connection_initialized();
    void *request = (void *) "{\"id\":\"1\",\"method\":\"protocol_translator_register\",\"jsonrpc\":\"2."
                             "0\",\"params\":{\"name\":\"test-pt\"}}";
    size_t request_len = 94;

    const char *expected_response = "{\"id\":\"1\",\"jsonrpc\":\"2.0\",\"result\":\"ok\"}";
    MyJsonFrameComparator comparator;
    MyJsonFrame response_frame = MyJsonFrame(expected_response);
    mock().installComparator("MyJsonFrame", comparator);

    mock().expectOneCall("lws_remaining_packet_payload").andReturnValue(0);
    mock().expectOneCall("lws_callback_on_writable").andReturnValue(1);
    mock().expectOneCall("lws_write").withParameterOfType("MyJsonFrame", "buf", (const void *) &response_frame);
    ValuePointer *pt_name_value_pointer = new ValuePointer((uint8_t *) "test-pt", strlen("test-pt"));
    mock().expectOneCall("set_resource_value")
            .withStringParameter("endpoint_name", NULL)
            .withParameter("object_id", PROTOCOL_TRANSLATOR_OBJECT_ID)
            .withParameter("object_instance_id", 0)
            .withParameter("resource_id", 0)
            .withParameterOfType("ValuePointer", "value", (const void *) pt_name_value_pointer)
            .withParameter("value_length", strlen("test-pt"))
            .withParameter("resource_type", 4)
            .withParameter("opr", 1)
            .withPointerParameter("ctx", NULL);

    uint16_t zero = 0;
    ValuePointer *device_amount_value_pointer = new ValuePointer((uint8_t *) &zero, sizeof(uint16_t));
    mock().expectOneCall("edgeclient_is_shutting_down").andReturnValue(false);
    mock().expectOneCall("set_resource_value")
            .withStringParameter("endpoint_name", NULL)
            .withParameter("object_id", PROTOCOL_TRANSLATOR_OBJECT_ID)
            .withParameter("object_instance_id", 0)
            .withParameter("resource_id", 1)
            .withParameterOfType("ValuePointer", "value", (const void *) device_amount_value_pointer)
            .withParameter("value_length", sizeof(uint16_t))
            .withParameter("resource_type", 1)
            .withParameter("opr", 1)
            .withPointerParameter("ctx", NULL);

    mock().expectOneCall("update_register_client_conditional");

    mock().expectOneCall("edge_mutex_init")
            .withPointerParameter("mutex", &rpc_mutex)
            .withIntParameter("type", PTHREAD_MUTEX_ERRORCHECK)
            .andReturnValue(0);
    init_protocol();
    server_test_call_receive_cb(test_ctx->connection, request, request_len);

    // Check for pending messages
    mock().expectOneCall("edge_mutex_lock").withPointerParameter("mutex", (void *) &rpc_mutex).andReturnValue(0);
    mock().expectOneCall("edge_mutex_unlock").withPointerParameter("mutex", (void *) &rpc_mutex).andReturnValue(0);
    mock().expectOneCall("remove_object_instance")
            .withStringParameter("endpoint_name", NULL)
            .withUnsignedIntParameter("object_id", PROTOCOL_TRANSLATOR_OBJECT_ID)
            .withUnsignedLongIntParameter("object_instance_id", 0);
    check_remove_resources_and_objects_owned_by_client(test_ctx->connection, 0 /* endpoints */);
    mock().expectOneCall("update_register_client_conditional");
    server_test_connection_closed(test_ctx->connection);
    CHECK_EQUAL(0, edgeserver_get_number_registered_endpoints_count());
    test_ctx->connection = NULL;
    mock().checkExpectations();
    free_test_context(test_ctx, 0 /* registered_translators*/, 0 /* not_accepted_translators */, 0 /* endpoints */);
    delete pt_name_value_pointer;
    delete device_amount_value_pointer;
    mock().checkExpectations();
}

TEST(protocol_api, test_edge_common_read_cb_data_frame_integer_request_id)
{
    struct test_context *test_ctx = connection_initialized();
    void *request = (void *) "{\"id\":1,\"method\":\"protocol_translator_register\",\"jsonrpc\":\"2."
                             "0\",\"params\":{\"name\":\"test-pt\"}}";
    size_t request_len = 92;

    const char *expected_response = "{\"id\":1,\"jsonrpc\":\"2.0\",\"result\":\"ok\"}";
    MyJsonFrameComparator comparator;
    MyJsonFrame response_frame = MyJsonFrame(expected_response);
    mock().installComparator("MyJsonFrame", comparator);

    mock().expectOneCall("lws_remaining_packet_payload").andReturnValue(0);
    mock().expectOneCall("lws_callback_on_writable").andReturnValue(1);
    mock().expectOneCall("lws_write").withParameterOfType("MyJsonFrame", "buf", (const void *) &response_frame);
    ValuePointer *pt_name_value_pointer = new ValuePointer((uint8_t *) "test-pt", strlen("test-pt"));
    mock().expectOneCall("set_resource_value")
            .withStringParameter("endpoint_name", NULL)
            .withParameter("object_id", PROTOCOL_TRANSLATOR_OBJECT_ID)
            .withParameter("object_instance_id", 0)
            .withParameter("resource_id", 0)
            .withParameterOfType("ValuePointer", "value", (const void *) pt_name_value_pointer)
            .withParameter("value_length", strlen("test-pt"))
            .withParameter("resource_type", 4)
            .withParameter("opr", 1)
            .withPointerParameter("ctx", NULL);

    uint16_t zero = 0;
    ValuePointer *device_amount_value_pointer = new ValuePointer((uint8_t *) &zero, sizeof(uint16_t));
    mock().expectOneCall("edgeclient_is_shutting_down").andReturnValue(false);
    mock().expectOneCall("set_resource_value")
            .withStringParameter("endpoint_name", NULL)
            .withParameter("object_id", PROTOCOL_TRANSLATOR_OBJECT_ID)
            .withParameter("object_instance_id", 0)
            .withParameter("resource_id", 1)
            .withParameterOfType("ValuePointer", "value", (const void *) device_amount_value_pointer)
            .withParameter("value_length", sizeof(uint16_t))
            .withParameter("resource_type", 1)
            .withParameter("opr", 1)
            .withPointerParameter("ctx", NULL);

    mock().expectOneCall("update_register_client_conditional");

    mock().expectOneCall("edge_mutex_init")
            .withPointerParameter("mutex", &rpc_mutex)
            .withIntParameter("type", PTHREAD_MUTEX_ERRORCHECK)
            .andReturnValue(0);
    init_protocol();
    server_test_call_receive_cb(test_ctx->connection, request, request_len);

    // Check for pending messages
    mock().expectOneCall("edge_mutex_lock").withPointerParameter("mutex", (void *) &rpc_mutex).andReturnValue(0);
    mock().expectOneCall("edge_mutex_unlock").withPointerParameter("mutex", (void *) &rpc_mutex).andReturnValue(0);
    mock().expectOneCall("remove_object_instance")
            .withStringParameter("endpoint_name", NULL)
            .withUnsignedIntParameter("object_id", PROTOCOL_TRANSLATOR_OBJECT_ID)
            .withUnsignedLongIntParameter("object_instance_id", 0);
    check_remove_resources_and_objects_owned_by_client(test_ctx->connection, 0 /* endpoints */);
    mock().expectOneCall("update_register_client_conditional");
    server_test_connection_closed(test_ctx->connection);
    CHECK_EQUAL(0, edgeserver_get_number_registered_endpoints_count());
    test_ctx->connection = NULL;
    mock().checkExpectations();
    free_test_context(test_ctx, 0 /* registered_translators*/, 0 /* not_accepted_translators */, 0 /* endpoints */);
    delete pt_name_value_pointer;
    delete device_amount_value_pointer;
    mock().checkExpectations();
}

TEST(protocol_api, test_edge_common_read_cb_incomplete_message)
{
    struct test_context *test_ctx = connection_initialized();
    void *request = (void *) "{\"id\":\"1\",\"method\":\"protocol_translator_register\",\"jsonrpc\":\"2."
                             "0\",\"params\":{\"name\":\"test-p"; // t\"}}"

    size_t request_len = 94; // Note: it really should be 98!

    mock().expectOneCall("edge_mutex_init")
            .withPointerParameter("mutex", &rpc_mutex)
            .withIntParameter("type", PTHREAD_MUTEX_ERRORCHECK)
            .andReturnValue(0);
    init_protocol();
    mock().expectOneCall("lws_remaining_packet_payload").andReturnValue(0);
    mock().expectOneCall("lws_callback_on_writable").andReturnValue(-1);
    check_remove_resources_and_objects_owned_by_client(test_ctx->connection, 0 /* endpoints */);
    mock().expectOneCall("update_register_client_conditional");
    server_test_call_receive_cb(test_ctx->connection, request, request_len);
    // Check for pending messages
    mock().expectOneCall("edge_mutex_lock").withPointerParameter("mutex", (void *) &rpc_mutex).andReturnValue(0);
    mock().expectOneCall("edge_mutex_unlock").withPointerParameter("mutex", (void *) &rpc_mutex).andReturnValue(0);
    server_test_connection_closed(test_ctx->connection);
    CHECK_EQUAL(0, edgeserver_get_number_registered_endpoints_count());
    test_ctx->connection = NULL;
    free_test_context(test_ctx,
                      0 /* registered_translators*/,
                      0 /* not_accepted_translators */,
                      0 /* registered_endpoints */);
    mock().checkExpectations();
}

TEST(protocol_api, test_write_data_websocket_add_message_while_not_closing)
{
    struct test_context *test_ctx = connection_initialized();
    ((websocket_connection_t*)test_ctx->connection->transport_connection->transport)->to_close = false;
    test_ctx->connection->connected = true;
    char *message = (char *) "{\"id\":\"1\",\"jsonrpc\":\"2.0\",\"result\":\"ok\"}";

    MyJsonFrameComparator comparator;
    mock().installComparator("MyJsonFrame", comparator);

    mock().expectOneCall("lws_callback_on_writable").andReturnValue(1);
    MyJsonFrame frame = MyJsonFrame(message, strlen(message));
    char *message_cpy = (char *) calloc(1, strlen(message) + 1);
    strcpy(message_cpy, message);
    mock().expectOneCall("lws_write").withParameterOfType("MyJsonFrame", "buf", (const void *) &frame);;
    int rc = edge_core_write_data_frame_websocket(test_ctx->connection, message_cpy, strlen(message));
    CHECK_EQUAL(0, rc);
    check_remove_resources_and_objects_owned_by_client(test_ctx->connection, 0 /* endpoints */);
    free_test_context(test_ctx, 0, 0, 0 /* endpoints */);
    mock().checkExpectations();
}

TEST(protocol_api, test_write_data_websocket_add_last_message_while_starting_to_close)
{
    struct test_context *test_ctx = connection_initialized();
    ((websocket_connection_t*)test_ctx->connection->transport_connection->transport)->to_close = false;
    test_ctx->connection->connected = false;
    char *message = (char *) "{\"error\":{\"code\":-30003,\"data\":\"Cannot register the protocol translator.\","
                             "\"message\":\"Protocol translator name reserved.\"},\"id\":\"0\",\"jsonrpc\":\"2.0\"}";

    MyJsonFrameComparator comparator;
    mock().installComparator("MyJsonFrame", comparator);

    mock().expectOneCall("lws_callback_on_writable").andReturnValue(1);
    MyJsonFrame frame = MyJsonFrame(message, strlen(message));
    char *message_cpy = (char*)calloc(1,strlen(message) + 1);
    strcpy(message_cpy, message);
    mock().expectOneCall("lws_write").withParameterOfType("MyJsonFrame", "buf", (const void *) &frame);;
    int rc = edge_core_write_data_frame_websocket(test_ctx->connection, message_cpy, strlen(message));
    CHECK_EQUAL(0, rc);
    check_remove_resources_and_objects_owned_by_client(test_ctx->connection, 0 /* endpoints */);
    free_test_context(test_ctx, 0, 0, 0 /* endpoints */);
    mock().checkExpectations();
}

TEST(protocol_api, test_write_data_websocket_add_message_while_already_closing)
{
    struct test_context *test_ctx = connection_initialized();
    ((websocket_connection_t*)test_ctx->connection->transport_connection->transport)->to_close = true;
    test_ctx->connection->connected = false;
    int rc = edge_core_write_data_frame_websocket(test_ctx->connection, (char *) "test", strlen("test"));
    CHECK_EQUAL(-1, rc);
    check_remove_resources_and_objects_owned_by_client(test_ctx->connection, 0 /* endpoints */);
    free_test_context(test_ctx, 0, 0, 0 /* endpoints */);

    mock().checkExpectations();
}

static void main_program(void *arg)
{
#define ARG_COUNT 5
    const char *argv[ARG_COUNT] = {"edge-core", "-p", "TEST_UNIX_SOCKET_PATH", "-o", "8080"};
    int32_t argc = ARG_COUNT;
    main_test_params_t *params = (main_test_params_t *) arg;
    edge_server_main_expectations_until_event_loop(argc, (char **) argv, params);
    testable_main((int) argc, (char **) argv);
}

typedef struct finish_frame_thread_params {
   main_test_params_t *params;
   struct test_context *test_ctx;
   bool create_connection;
   bool client_closes_first;
} finish_frame_thread_params_t;

static void *process_finish_frame_thread(void *arg)
{
    /*
     * This function tests different cases when the connection is closed:
     *   * The client closes the connection.
     *   * The client is killed.
     *   * The server closes with the connection.
     *   * The server closes without the connection.
     */
    finish_frame_thread_params_t *finish_params = (finish_frame_thread_params_t *) arg;
    main_test_params_t *params = finish_params->params;
    struct test_context *test_ctx = finish_params->test_ctx;
    evbase_mock_wait_until_event_loop(params->base);
    test_ctx->context = g_program_context;
    if (finish_params->create_connection) {
        mock().expectOneCall("lws_hdr_total_length")
            .withIntParameter("h", (int) WSI_TOKEN_GET_URI)
            .andReturnValue((int) strlen("/1/pt"));
        mock().expectOneCall("lws_hdr_copy")
            .withOutputParameterReturning("dest", "/1/pt", strlen("/1/pt"))
            .ignoreOtherParameters()
            .andReturnValue(1);
        test_ctx->connection = server_test_establish_connection();

        test_registers_successfully(test_ctx);
    }
    error_cb(1200, "test description");
    CHECK_EQUAL(0, strcmp(g_program_context->ctx_data->cloud_error->error_description, "test description"));
    CHECK_EQUAL(1200, g_program_context->ctx_data->cloud_error->error_code);
    CHECK_EQUAL(EDGE_STATE_ERROR, g_program_context->ctx_data->cloud_connection_status);
    register_cb();
    CHECK(g_program_context->ctx_data->cloud_connection_status == EDGE_STATE_CONNECTED);
    unregister_cb();
    CHECK(g_program_context->ctx_data->cloud_connection_status == EDGE_STATE_CONNECTING);
    if (finish_params->create_connection) {
        // Connection creation is tested
        struct pt_device_count_expectations *dce_register = pt_create_device_count_expectations("0", 1);

        ValuePointer *pt_resource_vp = check_creates_endpoint_expectations(test_ctx->connection, dce_register);

        struct json_message_t *userdata = create_endpoint(test_ctx->connection, TEST_DEVICE_REGISTER_JSON);

        if (finish_params->client_closes_first) {
            // Client closes
            expect_mutexing();
            check_remove_resources_and_objects_owned_by_client(test_ctx->connection, 1 /* endpoints */);
            mock().expectOneCall("remove_object_instance")
                    .withStringParameter("endpoint_name", NULL)
                    .withParameter("object_id", 26241)
                    .withParameter("object_instance_id", 0);
            mock().expectNCalls(1, "update_register_client_conditional");
            int32_t old_count = edgeserver_get_number_registered_endpoints_count();
            server_test_connection_closed(test_ctx->connection);
            int32_t new_count = edgeserver_get_number_registered_endpoints_count();
            CHECK_EQUAL(new_count, old_count - 1);
        } else {
            // Server closes
            CHECK_EQUAL(1, ns_list_count(&test_ctx->connection->ctx->ctx_data->registered_translators));
            mock().expectOneCall("remove_object_instance")
                    .withStringParameter("endpoint_name", NULL)
                    .withParameter("object_id", 26241)
                    .withParameter("object_instance_id", 0);
            mock().expectOneCall("lws_callback_on_writable").andReturnValue(-1);
            // Checking unresponded requests.
            mock().expectOneCall("edge_mutex_lock")
                    .withPointerParameter("mutex", (void *) &rpc_mutex)
                    .andReturnValue(0);
            mock().expectOneCall("edge_mutex_unlock")
                    .withPointerParameter("mutex", (void *) &rpc_mutex)
                    .andReturnValue(0);

            check_remove_resources_and_objects_owned_by_client(test_ctx->connection, 1);
        }
        deallocate_json_message_t(userdata);
        delete pt_resource_vp;
        free_pt_device_count_expectations(dce_register);
    }
    edgeserver_remove_protocol_translator_nodes();
    mock().expectOneCall("event_base_loopexit")
            .withPointerParameter("base", (void *) params->base)
            .withPointerParameter("tv", (void *) NULL);
    edge_server_main_expectations_after_event_loop(params);
    edgeserver_graceful_shutdown();

    if (finish_params->create_connection && !finish_params->client_closes_first) {
       // Server closed connection this simulates the connection closed callback.
        mock().expectNCalls(1, "update_register_client_conditional");
        server_test_connection_closed(test_ctx->connection);
    }
    mock().checkExpectations();
    return NULL;
}

static void test_graceful_shutdown(bool create_connection, bool client_closes_first)
{
    pthread_t interrupt_thread;
    mock().strictOrder();
    finish_frame_thread_params_t *finish_params = (finish_frame_thread_params_t *)
            calloc(1, sizeof(finish_frame_thread_params_t));
    finish_params->create_connection = create_connection;
    finish_params->client_closes_first = client_closes_first;
    main_test_params_t *params = edge_server_alloc_main_test_params(MAIN_TEST_EVENT_BASE_CREATION_SUCCEEDS);
    struct event_base *base = params->base;
    evbase_mock_setup_event_loop_wait(base);
    struct test_context *test_ctx = create_test_context(NULL);
    finish_params->test_ctx = test_ctx;
    finish_params->params = params;

    pthread_create(&interrupt_thread, NULL, process_finish_frame_thread, (void *) finish_params);
    main_program(params);
    evbase_mock_release_interrupt_thread(params->base);

    pthread_join(interrupt_thread, NULL);
    edge_server_delete_main_test_params(params);
    free(finish_params);
    free(test_ctx);
}

TEST(protocol_api_without_dummy_program_context, test_removes_connection_when_edge_core_interrupted)
{
    test_graceful_shutdown(true /* create_connection */, false /* client_closes_first */);
    mock().checkExpectations();
}

TEST(protocol_api_without_dummy_program_context, test_removes_connection_when_client_closes)
{
    test_graceful_shutdown(true /* create_connection */, true /* client_closes_first */);
    mock().checkExpectations();
}

TEST(protocol_api_without_dummy_program_context, test_exits_immediately_if_there_no_active_connections)
{
    test_graceful_shutdown(false /* create_connection */, false /* client_closes_first */);
    mock().checkExpectations();
}

TEST(protocol_api, test_multiple_items_in_hierarchy_levels)
{
    const int EXPECTED_ITEMS_PER_LEVEL = 2;
    // expected levels 3 (object, instance, resource)
    const int EXPECTED_VALUE_COUNT = (2 * 2 * 2) * EXPECTED_ITEMS_PER_LEVEL;

    struct test_context *test_ctx = protocol_translator_registered(0);

    /* Set expectations for endpoint structure */

    mock().expectOneCall("endpoint_exists")
        .withParameter("endpoint_name", "complex")
        .andReturnValue(0);

    mock().expectOneCall("endpoint_exists")
        .withParameter("endpoint_name", "complex")
        .andReturnValue(0);

    mock().expectOneCall("edgeclient_is_shutting_down").andReturnValue(false);
    mock().expectOneCall("add_endpoint")
        .withParameter("endpoint_name", "complex")
        .withParameter("ctx", test_ctx->connection)
        .andReturnValue(1);

    uint32_t *zero_val = (uint32_t*) calloc(1, sizeof(uint32_t));
    ValuePointer zero_int_value_pointer = ValuePointer((uint8_t*) zero_val, sizeof(uint32_t));
    uint8_t* zero_string = (uint8_t*) "0";
    ValuePointer zero_string_value_pointer = ValuePointer(zero_string, strlen("0"));

    ValuePointer *value_pointers[EXPECTED_VALUE_COUNT] = {0};
    int index = 0;
    for (int i = 0; i < EXPECTED_ITEMS_PER_LEVEL; i++) { // object
        for (int k = 0; k < EXPECTED_ITEMS_PER_LEVEL; k++) { // object instance
            for (int n = 0; n < EXPECTED_ITEMS_PER_LEVEL; n++) { // resource
                ValuePointer *vp = new ValuePointer();
                value_pointers[index] = vp;
                index++;
                if (n % 2 == 0) {
                    vp->copyFrom(zero_int_value_pointer);
                } else {
                    vp->copyFrom(zero_string_value_pointer);
                }
                uint32_t value_length = n % 2 == 0 ? sizeof(uint32_t) : strlen("0");
                int resource_type = n % 2 == 0 ? 1 : 0;
                mock().expectOneCall("edgeclient_verify_value")
                        .withParameterOfType("ValuePointer", "value", (const void *) vp)
                        .withParameter("value_length", value_length)
                        .withParameter("resource_type", resource_type)
                        .andReturnValue(true);
                mock().expectOneCall("set_resource_value")
                    .withStringParameter("endpoint_name", "complex")
                    .withParameter("object_id", i)
                    .withParameter("object_instance_id", k)
                    .withParameter("resource_id", n)
                    .withParameterOfType("ValuePointer", "value", (const void *) vp)
                    .withParameter("value_length", value_length)
                    .withParameter("resource_type", resource_type)
                    .withParameter("opr", OPERATION_READ)
                    .withPointerParameter("ctx", test_ctx->connection)
                    .andReturnValue(PT_API_SUCCESS);
            }
        }
    }

    mock().expectNCalls(2, "update_register_client_conditional");

    /* Set expectations for protocol translator resource */
    // mock().expectOneCall("edgeclient_is_shutting_down").andReturnValue(false);
    struct pt_device_count_expectations *dce =
        pt_create_device_count_expectations("0", 1);

    mock().expectOneCall("get_resource_value")
            .withStringParameter("endpoint_name", NULL)
            .withParameter("object_id", PROTOCOL_TRANSLATOR_OBJECT_ID)
            .withParameter("object_instance_id", 0)
            .withParameter("resource_id", PROTOCOL_TRANSLATOR_OBJECT_COUNT_RESOURCE_ID)
            .withOutputParameterReturning("value", &dce->get_resource_value, sizeof(uint16_t *))
            .withOutputParameterReturning("value_length", dce->get_value_size, sizeof(uint32_t));

    ValuePointer value_pointer = ValuePointer((uint8_t*) dce->set_resource_value, *dce->set_value_size);

    mock().expectOneCall("set_resource_value")
            .withStringParameter("endpoint_name", NULL)
            .withParameter("object_id", PROTOCOL_TRANSLATOR_OBJECT_ID)
            .withParameter("object_instance_id", 0)
            .withParameter("resource_id", PROTOCOL_TRANSLATOR_OBJECT_COUNT_RESOURCE_ID)
            .withParameterOfType("ValuePointer", "value", (const void *) &value_pointer)
            .withParameter("value_length", sizeof(uint16_t))
            .withParameter("resource_type", LWM2M_INTEGER)
            .withParameter("opr", OPERATION_READ)
            .withPointerParameter("ctx", test_ctx->connection)
            .andReturnValue(PT_API_SUCCESS);

    struct json_message_t *userdata = create_endpoint(test_ctx->connection, TEST_COMPLEX_HIERARCHY_JSON);

    for (int i = 0; i < EXPECTED_VALUE_COUNT; i++) {
        delete value_pointers[i];
    }
    free(zero_val);
    free_pt_device_count_expectations(dce);
    deallocate_json_message_t(userdata);

    check_connection_free_expectations(test_ctx->connection, 26241, 0, 1 /* endpoints */);
    free_test_context(test_ctx, 0, 0, 1);
    mock().checkExpectations();
}

TEST(protocol_api, test_certificate_renewal_list_no_request_id)
{
    struct test_context *test_ctx = protocol_translator_registered(0);

    // Init certificate list set parameter structure
    json_t *params = json_object();

    // Build certificate list set jsonrpc structure
    json_t *request = json_object();
    json_object_set_new(request, "jsonrpc", json_string("2.0"));
    json_object_set_new(request, "method", json_string("certificate_renewal_list_set"));
    json_object_set_new(request, "params", params);

    char *data = json_dumps(request, JSON_COMPACT);
    struct json_message_t *userdata = alloc_json_message_t(data, strlen(data), test_ctx->connection);
    free(data);

    json_t *result;
    // Edge core shutting down
    mock().expectOneCall("edgeclient_is_shutting_down").andReturnValue(false);
    int rc = certificate_renewal_list_set(request, params, &result, userdata);
    CHECK_EQUAL(1, rc);
    CHECK(result != NULL);
    json_t *code_obj = json_object_get(result, "code");
    CHECK_EQUAL(JSONRPC_INVALID_PARAMS, json_integer_value(code_obj));
    json_decref(result);
    json_decref(request);

    check_connection_free_expectations(test_ctx->connection, 26241, 0, 0 /* endpoints */);
    deallocate_json_message_t(userdata);

    free_test_context(test_ctx, 0 /* registered_translators*/, 0 /* not_accepted_translators */, 0 /* endpoints */);
    mock().checkExpectations();
}

TEST(protocol_api, test_certificate_renewal_list_invalid_parameters)
{
    struct test_context* test_ctx = protocol_translator_registered(0);

    // Init certificate list set parameter structure
    json_t *params = json_object();

    // Build certificate list set jsonrpc structure
    json_t *request = json_object();
    json_object_set_new(request, "jsonrpc", json_string("2.0"));
    json_object_set_new(request, "id", json_string("1"));
    json_object_set_new(request, "method", json_string("certificate_renewal_list_set"));
    json_object_set_new(request, "params", params);

    char *data = json_dumps(request, JSON_COMPACT);
    struct json_message_t *userdata = alloc_json_message_t(data, strlen(data), test_ctx->connection);
    free(data);

    json_t *result;

    // Invalid parameters
    mock().expectOneCall("edgeclient_is_shutting_down").andReturnValue(false);
    int rc = certificate_renewal_list_set(request, params, &result, userdata);
    CHECK_EQUAL(1, rc);
    json_t *code_obj = json_object_get(result, "code");
    CHECK(result != NULL);
    CHECK_EQUAL(JSONRPC_INVALID_PARAMS, json_integer_value(code_obj));

    json_decref(result);
    json_decref(request);

    check_connection_free_expectations(test_ctx->connection, 26241, 0, 0 /* endpoints */);
    deallocate_json_message_t(userdata);

    free_test_context(test_ctx, 0 /* registered_translators*/, 0 /* not_accepted_translators */, 0 /* endpoints */);
    mock().checkExpectations();
}

TEST(protocol_api, test_certificate_renewal_list_set)
{
    struct test_context* test_ctx = protocol_translator_registered(0);

    // Init certificate arrays
    json_t *empty_array = json_array();
    json_t *cert_array = json_array();
    json_array_append_new(cert_array, json_string("test-certificate-name"));
    json_array_append_new(cert_array, json_string("")); // Empty string should be ignored
    json_array_append_new(cert_array, json_string("test-certificate-name")); // Duplicates are fine
    json_array_append_new(cert_array, json_string("some-cert"));
    json_t *params = json_object();
    json_object_set_new(params, "certificates", cert_array);

    // Build certificate list set jsonrpc structure
    json_t *request = json_object();
    json_object_set_new(request, "jsonrpc", json_string("2.0"));
    json_object_set_new(request, "id", json_string("1"));
    json_object_set_new(request, "method", json_string("certificate_renewal_list_set"));
    json_object_set_new(request, "params", params);

    char *data = json_dumps(request, JSON_COMPACT);
    struct json_message_t *userdata = alloc_json_message_t(data, strlen(data), test_ctx->connection);
    free(data);

    json_t *result;

    // Test setting certificate list with multiple certs
    mock().expectOneCall("edgeclient_is_shutting_down").andReturnValue(false);
    int rc = certificate_renewal_list_set(request, params, &result, userdata);

    // Check return value and result
    CHECK_EQUAL(0, rc);
    CHECK(result != NULL);
    STRCMP_EQUAL("ok", json_string_value(result));

    // Check certificate list in client data context
    CHECK_EQUAL(3, ns_list_count(&test_ctx->connection->client_data->certificate_list));
    string_list_entry_t *cert_entry = ns_list_get_first(&test_ctx->connection->client_data->certificate_list);
    CHECK(cert_entry != NULL);
    STRCMP_EQUAL("test-certificate-name", cert_entry->string);
    cert_entry = ns_list_get_next(&test_ctx->connection->client_data->certificate_list, cert_entry);
    CHECK(cert_entry != NULL);
    STRCMP_EQUAL("test-certificate-name", cert_entry->string);
    cert_entry = ns_list_get_next(&test_ctx->connection->client_data->certificate_list, cert_entry);
    CHECK(cert_entry != NULL);
    STRCMP_EQUAL("some-cert", cert_entry->string);

    json_decref(result);

    // Test setting empty certificate list
    json_object_set(params, "certificates", empty_array);
    mock().expectOneCall("edgeclient_is_shutting_down").andReturnValue(false);
    rc = certificate_renewal_list_set(request, params, &result, userdata);

    // Check return value and result
    CHECK_EQUAL(0, rc);
    CHECK(result != NULL);
    STRCMP_EQUAL("ok", json_string_value(result));

    // Check that list is empty
    CHECK_EQUAL(0, ns_list_count(&test_ctx->connection->client_data->certificate_list));

    json_decref(result);
    json_decref(request);
    json_decref(empty_array);

    check_connection_free_expectations(test_ctx->connection, 26241, 0, 0 /* endpoints */);
    deallocate_json_message_t(userdata);

    free_test_context(test_ctx, 0 /* registered_translators*/, 0 /* not_accepted_translators */, 0 /* endpoints */);
    mock().checkExpectations();
}

TEST(protocol_api, test_renew_certificate_no_request_id)
{
    struct test_context *test_ctx = protocol_translator_registered(0);

    // Build rpc request object
    json_t *request = json_object();
    json_t *params = json_object();
    json_object_set_new(request, "jsonrpc", json_string("2.0"));
    json_object_set_new(request, "method", json_string("renew_certificate"));
    json_object_set_new(request, "params", params);

    char *data = json_dumps(request, JSON_COMPACT);
    struct json_message_t *userdata = alloc_json_message_t(data, strlen(data), test_ctx->connection);
    free(data);

    json_t *result;

    // Edge core shutting down
    mock().expectOneCall("edgeclient_is_shutting_down").andReturnValue(false);
    int rc = renew_certificate(request, params, &result, userdata);
    CHECK_EQUAL(1, rc);
    CHECK(result != NULL);
    json_t *code_obj = json_object_get(result, "code");
    CHECK_EQUAL(JSONRPC_INVALID_PARAMS, json_integer_value(code_obj));
    mock().checkExpectations();
    json_decref(request);
    json_decref(result);
    check_connection_free_expectations(test_ctx->connection, 26241, 0, 0 /* endpoints */);
    deallocate_json_message_t(userdata);
    free_test_context(test_ctx, 0 /* registered_translators*/, 0 /* not_accepted_translators */, 0 /* endpoints */);
}

TEST(protocol_api, test_renew_certificate_invalid_parameters)
{
    struct test_context* test_ctx = protocol_translator_registered(0);

    // Init rpc params objects:
    // 1. with missing certificate field
    // 2. with empty certificate field
    // 3. with certificate that is not set in certificate list
    json_t *empty_params = json_object();
    json_t *empty_cert_params = json_object();
    json_object_set_new(empty_cert_params, "certificate", json_string(""));
    json_t *cert_params = json_object();
    json_object_set_new(empty_cert_params, "certificate", json_string("test-certificate"));

    // Build rpc request object
    json_t *request = json_object();
    json_object_set_new(request, "jsonrpc", json_string("2.0"));
    json_object_set_new(request, "id", json_string("1"));
    json_object_set_new(request, "method", json_string("renew_certificate"));
    json_object_set_new(request, "params", empty_params);

    char *data = json_dumps(request, JSON_COMPACT);
    struct json_message_t *userdata = alloc_json_message_t(data, strlen(data), test_ctx->connection);
    free(data);

    json_t *result;

    // Empty params
    mock().expectOneCall("edgeclient_is_shutting_down").andReturnValue(false);
    int rc = renew_certificate(request, empty_params, &result, userdata);
    CHECK_EQUAL(1, rc);
    json_t *code_obj = json_object_get(result, "code");
    CHECK(result != NULL);
    CHECK_EQUAL(JSONRPC_INVALID_PARAMS, json_integer_value(code_obj));

    json_decref(result);

    // Empty certificate name field
    mock().expectOneCall("edgeclient_is_shutting_down").andReturnValue(false);
    json_object_set(request, "params", empty_cert_params);
    rc = renew_certificate(request, empty_cert_params, &result, userdata);
    CHECK_EQUAL(1, rc);
    code_obj = json_object_get(result, "code");
    CHECK(result != NULL);
    CHECK_EQUAL(JSONRPC_INVALID_PARAMS, json_integer_value(code_obj));

    json_decref(result);

    // Certificate not in certificate renewal list
    mock().expectOneCall("edgeclient_is_shutting_down").andReturnValue(false);
    json_object_set(request, "params", cert_params);
    rc = renew_certificate(request, cert_params, &result, userdata);
    CHECK_EQUAL(1, rc);
    code_obj = json_object_get(result, "code");
    CHECK(result != NULL);
    CHECK_EQUAL(JSONRPC_INVALID_PARAMS, json_integer_value(code_obj));

    json_decref(result);

    // Clean up
    json_decref(request);
    json_decref(cert_params);
    json_decref(empty_cert_params);

    check_connection_free_expectations(test_ctx->connection, 26241, 0, 0 /* endpoints */);
    deallocate_json_message_t(userdata);

    free_test_context(test_ctx, 0 /* registered_translators*/, 0 /* not_accepted_translators */, 0 /* endpoints */);
    mock().checkExpectations();
}

TEST(protocol_api, test_renew_certificate_successful_initiation)
{
    struct test_context* test_ctx = protocol_translator_registered(0);

    // Init rpc params object, one with missing and one with empty certificate field
    json_t *params = json_object();
    json_object_set_new(params, "certificate", json_string("test-certificate"));

    // Add the certificate to certificate list for client
    string_list_entry_t cert_entry = {0};
    cert_entry.string = strdup("test-certificate");
    client_data_t *client_data = test_ctx->connection->client_data;

    ns_list_add_to_end(&client_data->certificate_list, &cert_entry);

    // Build rpc request object
    json_t *request = json_object();
    json_object_set_new(request, "jsonrpc", json_string("2.0"));
    json_object_set_new(request, "id", json_string("1"));
    json_object_set_new(request, "method", json_string("renew_certificate"));
    json_object_set_new(request, "params", params);

    char *data = json_dumps(request, JSON_COMPACT);
    struct json_message_t *userdata = alloc_json_message_t(data, strlen(data), test_ctx->connection);
    free(data);

    json_t *result;

    // Successful initiation
    int detailed_error = 0;
    mock().expectOneCall("edgeclient_is_shutting_down").andReturnValue(false);
    mock().expectOneCall("edgeclient_renew_certificate")
            .withStringParameter("cert_name", "test-certificate")
            .withOutputParameterReturning("detailed_error", &detailed_error, sizeof(detailed_error))
            .andReturnValue(PT_API_SUCCESS);
    int rc = renew_certificate(request, params, &result, userdata);
    CHECK_EQUAL(0, rc);
    CHECK(result != NULL);
    STRCMP_EQUAL("ok", json_string_value(result));
    json_decref(result);
    json_decref(request);

    check_connection_free_expectations(test_ctx->connection, 26241, 0, 0 /* endpoints */);
    deallocate_json_message_t(userdata);

    ns_list_remove(&test_ctx->connection->client_data->certificate_list, &cert_entry);
    free(cert_entry.string);

    free_test_context(test_ctx, 0 /* registered_translators*/, 0 /* not_accepted_translators */, 0 /* endpoints */);
    mock().checkExpectations();
}

TEST(protocol_api, test_renew_certificate_failures)
{
    struct test_context* test_ctx = protocol_translator_registered(0);

    // Init rpc params object, one with missing and one with empty certificate field
    json_t *params = json_object();
    json_object_set_new(params, "certificate", json_string("test-certificate"));

    // Add the certificate to certificate list for client
    string_list_entry_t cert_entry = {0};
    cert_entry.string = strdup("test-certificate");
    ns_list_add_to_end(&test_ctx->connection->client_data->certificate_list, &cert_entry);

    // Build rpc request object
    json_t *request = json_object();
    json_object_set_new(request, "jsonrpc", json_string("2.0"));
    json_object_set_new(request, "id", json_string("1"));
    json_object_set_new(request, "method", json_string("renew_certificate"));
    json_object_set_new(request, "params", params);

    char *data = json_dumps(request, JSON_COMPACT);
    struct json_message_t *userdata = alloc_json_message_t(data, strlen(data), test_ctx->connection);
    free(data);

    json_t *result;

    // Certificate renewal busy error
    int detailed_error = CE_STATUS_DEVICE_BUSY;
    mock().expectOneCall("edgeclient_is_shutting_down").andReturnValue(false);
    mock().expectOneCall("edgeclient_renew_certificate")
            .withStringParameter("cert_name", "test-certificate")
            .withOutputParameterReturning("detailed_error", &detailed_error, sizeof(detailed_error))
            .andReturnValue(PT_API_CERTIFICATE_RENEWAL_BUSY);
    int rc = renew_certificate(request, params, &result, userdata);
    CHECK_EQUAL(1, rc);
    json_t *code_obj = json_object_get(result, "code");
    CHECK(result != NULL);
    CHECK_EQUAL(PT_API_CERTIFICATE_RENEWAL_BUSY, json_integer_value(code_obj));

    json_decref(result);

    // Certificate renewal generic error
    int detailed_error2 = CE_STATUS_ERROR;
    mock().expectOneCall("edgeclient_is_shutting_down").andReturnValue(false);
    mock().expectOneCall("edgeclient_renew_certificate")
            .withStringParameter("cert_name", "test-certificate")
            .withOutputParameterReturning("detailed_error", &detailed_error2, sizeof(int))
            .andReturnValue(PT_API_CERTIFICATE_RENEWAL_ERROR);
    rc = renew_certificate(request, params, &result, userdata);
    CHECK_EQUAL(1, rc);
    code_obj = json_object_get(result, "code");
    json_t *data_obj = json_object_get(result, "data");
    CHECK(result != NULL);
    CHECK_EQUAL(PT_API_CERTIFICATE_RENEWAL_ERROR, json_integer_value(code_obj));
    STRCMP_EQUAL("Certificate renewal failed. Certificate enrollment client gave error 1280 (CE_STATUS_ERROR).",
                 json_string_value(data_obj));

    json_decref(result);

    json_decref(request);

    check_connection_free_expectations(test_ctx->connection, 26241, 0, 0 /* endpoints */);
    deallocate_json_message_t(userdata);

    ns_list_remove(&test_ctx->connection->client_data->certificate_list, &cert_entry);
    free(cert_entry.string);

    free_test_context(test_ctx, 0 /* registered_translators*/, 0 /* not_accepted_translators */, 0 /* endpoints */);
    mock().checkExpectations();
}

static void test_certificate_renewal_notifier(bool successful_response)
{
    struct test_context *test_ctx = protocol_translator_registered(0);

    // NULL context
    CHECK_EQUAL(1, certificate_renewal_notifier("test-certificate", CE_STATUS_SUCCESS, CE_INITIATOR_DEVICE, NULL));

    // Empty PT list, no one to notify
    connection_elem_list pt_list;
    ns_list_init(&pt_list);

    CHECK_EQUAL(0, certificate_renewal_notifier("test-certificate", CE_STATUS_SUCCESS, CE_INITIATOR_DEVICE, &pt_list));

    // Add PT
    struct connection_list_elem *new_translator = (connection_list_elem*)calloc(1, sizeof(struct connection_list_elem));
    new_translator->conn = test_ctx->connection;
    ns_list_add_to_end(&test_ctx->context->ctx_data->registered_translators, new_translator);

    // PT has not added cert to list
    CHECK_EQUAL(0,
                certificate_renewal_notifier("test-certificate",
                                             CE_STATUS_SUCCESS,
                                             CE_INITIATOR_DEVICE,
                                             &test_ctx->context->ctx_data->registered_translators));

    // PT has added certificate to list
    string_list_entry_t cert_entry = {0};
    cert_entry.string = strdup("test-certificate");
    client_data_t *client_data = test_ctx->connection->client_data;
    client_data->registered = true;

    // Add cert to pt's cert list
    ns_list_add_to_end(&client_data->certificate_list, &cert_entry);

    const char *expected_data =
            "{\"id\":\"1\",\"jsonrpc\":\"2.0\",\"method\":\"certificate_renewal_result\",\"params\":{"
            "\"certificate\":\"test-certificate\",\"description\":\"CE_STATUS_SUCCESS\",\"initiator\":0,\"status\":0}}";
    MyJsonFrameComparator comparator;
    MyJsonFrame frame = MyJsonFrame(expected_data);
    mock().installComparator("MyJsonFrame", comparator);
    mock().expectOneCall("lws_callback_on_writable").andReturnValue(1);
    mock().expectOneCall("lws_write").withParameterOfType("MyJsonFrame", "buf", (const void *) &frame);
    expect_mutexing();
    CHECK_EQUAL(0,
                certificate_renewal_notifier("test-certificate",
                                             CE_STATUS_SUCCESS,
                                             CE_INITIATOR_DEVICE,
                                             &test_ctx->context->ctx_data->registered_translators));
    char *response;
    if (successful_response) {
        response = strdup("{\"id\":\"1\",\"jsonrpc\":\"2.0\",\"result\":\"ok\"}");
    } else {
        response = strdup("{\"id\":\"1\",\"jsonrpc\":\"2.0\",\"error\":{\"code\":-1,\"message\": \"Catastrophical "
                          "failure\",\"data\":\"Can't do it!\"}}");
    }
    bool protocol_error;

    expect_mutexing();
    int rc = rpc_handle_message(response,
                                strlen(response),
                                test_ctx->connection,
                                (jsonrpc_method_entry_t *) client_data->method_table,
                                rpc_write_func_mock,
                                &protocol_error,
                                false /* mutex_acquired */);
    CHECK_EQUAL(0, rc);
    CHECK_EQUAL(false, protocol_error);

    ns_list_remove(&client_data->certificate_list, &cert_entry);
    free(cert_entry.string);

    check_connection_free_expectations(test_ctx->connection, 26241, 0, 0 /* endpoints */);
    free_test_context(test_ctx, 1 /* registered_translators*/, 0 /* not_accepted_translators */, 0 /* endpoints */);
    free(response);
    mock().checkExpectations();
}

TEST(protocol_api, test_certificate_renewal_notifier_success)
{
    test_certificate_renewal_notifier(true /* successful response */);
}

TEST(protocol_api, test_certificate_renewal_notifier_failure)
{
    test_certificate_renewal_notifier(false /* successful response */);
}

const char *cert_data_base64 =
    "MIIBvjCCAWOgAwIBAgIUZuKPY4VL1d9mxtPbHWQfYZ3JV0MwCgYIKoZIzj0EAwIwWDETMBEGA1UECgwKQ2xvdWRGbGFyZTEcMBoGA1UEAw"
    "wTY2xvdWRmbGFyZS1sZWFmLmNvbTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzELMAkGA1UEBhMCVVMwHhcNMTkwNDA0MTAxOTAwWhcNMTkw"
    "NTA0MTAxOTAwWjAfMR0wGwYDVQQDDBRkZXZpY2VfZW5kcG9pbnRfbmFtZTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABLb9AjsFQ13Z+"
    "f/VW0/"
    "4dQO50cb4ivQ50ev9YxHv+vdcw+pnaEqqD++xh6EEfol7BbDTRkJW+"
    "3WcRqa0QAecuOGjRDBCMBMGA1UdJQQMMAoGCCsGAQUFBwMCMAwGA1UdEwEB/"
    "wQCMAAwHQYDVR0OBBYEFB6I2FPoD9b7KdAJzIrE7Y7AfEbJMAoGCCqGSM49BAMCA0kAMEYCIQCVNJ5crLz2XztX0/"
    "doNlse6OGRsSeOhWQKsjm6WiNCMgIhAKVIPxXNeFSasvrBSxxK4wPz2/h/g9qtEeSit+N8np+8";
const char *certificate_name = "test-certificate";

TEST(protocol_api, test_get_certificate_exists)
{
    size_t binary_len = apr_base64_decode_len(cert_data_base64);
    unsigned char *cert_data_binary = (unsigned char *) calloc(1, binary_len);
    apr_base64_decode_binary(cert_data_binary, cert_data_base64);

    struct test_context *test_ctx = connection_initialized();
    test_registers_successfully(test_ctx);
    // Init rpc params object, one with missing and one with empty certificate field
    json_t *params = json_object();
    json_object_set_new(params, "certificate", json_string(certificate_name));

    // Build rpc request object
    json_t *request = json_object();
    json_object_set_new(request, "jsonrpc", json_string("2.0"));
    json_object_set_new(request, "id", json_string("1"));
    json_object_set_new(request, "method", json_string("crypto_get_certificate"));
    json_object_set_new(request, "params", params);

    char *data = json_dumps(request, JSON_COMPACT);
    struct json_message_t *userdata = alloc_json_message_t(data, strlen(data), test_ctx->connection);
    free(data);
    json_t *result = NULL;
    mock().expectOneCall("edgeclient_is_shutting_down").andReturnValue(false);
    mock().expectOneCall("eventOS_event_send")
            .withIntParameter("event_id", CRYPTO_API_EVENT_GET_CERTIFICATE)
            .withIntParameter("receiver", crypto_api_tasklet_id)
            .andReturnValue(0);
    int status = crypto_api_get_certificate(request, params, &result, userdata);
    CHECK_EQUAL(-1, status);
    mock().expectOneCall("kcm_item_get_data_size")
            .withStringParameter("kcm_item_data", certificate_name)
            .withIntParameter("kcm_item_name_len", strlen(certificate_name))
            .withIntParameter("kcm_item_type", KCM_CERTIFICATE_ITEM)
            .withOutputParameterReturning("kcm_item_data_size_out", &binary_len, sizeof(size_t))
            .andReturnValue(KCM_STATUS_SUCCESS);
    mock().expectOneCall("kcm_item_get_data")
            .withStringParameter("kcm_item_data", certificate_name)
            .withIntParameter("kcm_item_name_len", strlen(certificate_name))
            .withIntParameter("kcm_item_type", KCM_CERTIFICATE_ITEM)
            .withOutputParameterReturning("kcm_item_data_out", cert_data_binary, binary_len)
            .withOutputParameterReturning("kcm_item_data_act_size_out", &binary_len, sizeof(size_t))
            .andReturnValue(KCM_STATUS_SUCCESS);
    mock().expectOneCall("lws_callback_on_writable").andReturnValue(1);
    char *expected_data = NULL;
    asprintf(&expected_data,
             "{\"id\":\"1\",\"jsonrpc\":\"2.0\",\"result\":{\"certificate_data\":\"%s\",\"certificate_name\":\"%s\"}}",
             cert_data_base64,
             certificate_name);
    MyJsonFrame frame = MyJsonFrame(expected_data);
    MyJsonFrameComparator comparator;
    mock().installComparator("MyJsonFrame", comparator);

    expect_event_message_without_get_base(g_program_context->ev_base, safe_response_callback, true /* succeeds */);
    CHECK_EQUAL(true, eventOS_mock_event_handle());
    mock().expectOneCall("lws_write").withParameterOfType("MyJsonFrame", "buf", (const void *) &frame);
    evbase_mock_call_assigned_event_cb(g_program_context->ev_base, true);

    check_connection_free_expectations(test_ctx->connection, 26241, 0, 0 /* endpoints */);
    free_test_context(test_ctx, 1 /* registered_translators*/, 0 /* not_accepted_translators */, 0 /* endpoints */);

    mock().checkExpectations();
    deallocate_json_message_t(userdata);
    free(cert_data_binary);
    free(expected_data);
    json_decref(request);
}

TEST(protocol_api, test_get_certificate_exists_disconnected_during_sending)
{
    size_t binary_len = apr_base64_decode_len(cert_data_base64);
    unsigned char *cert_data_binary = (unsigned char *) calloc(1, binary_len);
    apr_base64_decode_binary(cert_data_binary, cert_data_base64);

    struct test_context *test_ctx = connection_initialized();
    test_registers_successfully(test_ctx);
    // Init rpc params object, one with missing and one with empty certificate field
    json_t *params = json_object();
    json_object_set_new(params, "certificate", json_string(certificate_name));

    // Build rpc request object
    json_t *request = json_object();
    json_object_set_new(request, "jsonrpc", json_string("2.0"));
    json_object_set_new(request, "id", json_string("1"));
    json_object_set_new(request, "method", json_string("crypto_get_certificate"));
    json_object_set_new(request, "params", params);

    char *data = json_dumps(request, JSON_COMPACT);
    struct json_message_t *userdata = alloc_json_message_t(data, strlen(data), test_ctx->connection);
    free(data);
    json_t *result = NULL;
    mock().expectOneCall("edgeclient_is_shutting_down").andReturnValue(false);
    mock().expectOneCall("eventOS_event_send")
            .withIntParameter("event_id", CRYPTO_API_EVENT_GET_CERTIFICATE)
            .withIntParameter("receiver", crypto_api_tasklet_id)
            .andReturnValue(0);
    int status = crypto_api_get_certificate(request, params, &result, userdata);
    CHECK_EQUAL(-1, status);
    mock().expectOneCall("kcm_item_get_data_size")
            .withStringParameter("kcm_item_data", certificate_name)
            .withIntParameter("kcm_item_name_len", strlen(certificate_name))
            .withIntParameter("kcm_item_type", KCM_CERTIFICATE_ITEM)
            .withOutputParameterReturning("kcm_item_data_size_out", &binary_len, sizeof(size_t))
            .andReturnValue(KCM_STATUS_SUCCESS);
    mock().expectOneCall("kcm_item_get_data")
            .withStringParameter("kcm_item_data", certificate_name)
            .withIntParameter("kcm_item_name_len", strlen(certificate_name))
            .withIntParameter("kcm_item_type", KCM_CERTIFICATE_ITEM)
            .withOutputParameterReturning("kcm_item_data_out", cert_data_binary, binary_len)
            .withOutputParameterReturning("kcm_item_data_act_size_out", &binary_len, sizeof(size_t))
            .andReturnValue(KCM_STATUS_SUCCESS);

    expect_event_message_without_get_base(g_program_context->ev_base, safe_response_callback, true /* succeeds */);
    CHECK_EQUAL(true, eventOS_mock_event_handle());
    // Disconnect in the middle of processing!
    check_connection_free_expectations(test_ctx->connection, 26241, 0, 0 /* endpoints */);
    free_test_context(test_ctx, 1 /* registered_translators*/, 0 /* not_accepted_translators */, 0 /* endpoints */);

    evbase_mock_call_assigned_event_cb(g_program_context->ev_base, true);

    mock().checkExpectations();
    deallocate_json_message_t(userdata);
    free(cert_data_binary);
    json_decref(request);
}

TEST(protocol_api, test_get_certificate_exists_msg_api_fails)
{
    size_t binary_len = apr_base64_decode_len(cert_data_base64);
    unsigned char *cert_data_binary = (unsigned char *) calloc(1, binary_len);
    apr_base64_decode_binary(cert_data_binary, cert_data_base64);

    struct test_context *test_ctx = connection_initialized();
    test_registers_successfully(test_ctx);
    // Init rpc params object, one with missing and one with empty certificate field
    json_t *params = json_object();
    json_object_set_new(params, "certificate", json_string(certificate_name));

    // Build rpc request object
    json_t *request = json_object();
    json_object_set_new(request, "jsonrpc", json_string("2.0"));
    json_object_set_new(request, "id", json_string("1"));
    json_object_set_new(request, "method", json_string("crypto_get_certificate"));
    json_object_set_new(request, "params", params);

    char *data = json_dumps(request, JSON_COMPACT);
    struct json_message_t *userdata = alloc_json_message_t(data, strlen(data), test_ctx->connection);
    free(data);
    json_t *result = NULL;
    mock().expectOneCall("edgeclient_is_shutting_down").andReturnValue(false);
    mock().expectOneCall("eventOS_event_send")
            .withIntParameter("event_id", CRYPTO_API_EVENT_GET_CERTIFICATE)
            .withIntParameter("receiver", crypto_api_tasklet_id)
            .andReturnValue(0);
    int status = crypto_api_get_certificate(request, params, &result, userdata);
    CHECK_EQUAL(-1, status);
    mock().expectOneCall("kcm_item_get_data_size")
            .withStringParameter("kcm_item_data", certificate_name)
            .withIntParameter("kcm_item_name_len", strlen(certificate_name))
            .withIntParameter("kcm_item_type", KCM_CERTIFICATE_ITEM)
            .withOutputParameterReturning("kcm_item_data_size_out", &binary_len, sizeof(size_t))
            .andReturnValue(KCM_STATUS_SUCCESS);
    mock().expectOneCall("kcm_item_get_data")
            .withStringParameter("kcm_item_data", certificate_name)
            .withIntParameter("kcm_item_name_len", strlen(certificate_name))
            .withIntParameter("kcm_item_type", KCM_CERTIFICATE_ITEM)
            .withOutputParameterReturning("kcm_item_data_out", cert_data_binary, binary_len)
            .withOutputParameterReturning("kcm_item_data_act_size_out", &binary_len, sizeof(size_t))
            .andReturnValue(KCM_STATUS_SUCCESS);
    expect_event_message_without_get_base(g_program_context->ev_base, safe_response_callback, false /* succeeds */);
    CHECK_EQUAL(true, eventOS_mock_event_handle());
    check_connection_free_expectations(test_ctx->connection, 26241, 0, 0 /* endpoints */);
    free_test_context(test_ctx, 1 /* registered_translators*/, 0 /* not_accepted_translators */, 0 /* endpoints */);

    mock().checkExpectations();
    deallocate_json_message_t(userdata);
    free(cert_data_binary);
    json_decref(request);
}

TEST(protocol_api, test_get_certificate_exists_internal_error)
{
    struct test_context *test_ctx = protocol_translator_registered(0);

    // Init rpc params object, one with missing and one with empty certificate field
    json_t *params = json_object();
    json_object_set_new(params, "certificate", json_string(certificate_name));

    // Build rpc request object
    json_t *request = json_object();
    json_object_set_new(request, "jsonrpc", json_string("2.0"));
    json_object_set_new(request, "id", json_string("1"));
    json_object_set_new(request, "method", json_string("crypto_get_certificate"));
    json_object_set_new(request, "params", params);

    char *data = json_dumps(request, JSON_COMPACT);
    struct json_message_t *userdata = alloc_json_message_t(data, strlen(data), test_ctx->connection);
    free(data);
    json_t *result = NULL;
    mock().expectOneCall("edgeclient_is_shutting_down").andReturnValue(false);
    mock().expectOneCall("eventOS_event_send")
            .withIntParameter("event_id", CRYPTO_API_EVENT_GET_CERTIFICATE)
            .withIntParameter("receiver", crypto_api_tasklet_id)
            .andReturnValue(1);
    int status = crypto_api_get_certificate(request, params, &result, userdata);
    CHECK_EQUAL(1, status);
    char *response_str = json_dumps(result, JSON_COMPACT);
    STRCMP_EQUAL("{\"code\":-30000,\"message\":\"Protocol translator API internal error.\",\"data\":\"Could not send "
                 "crypto API event.\"}",
                 response_str);

    check_connection_free_expectations(test_ctx->connection, 26241, 0, 0 /* endpoints */);
    deallocate_json_message_t(userdata);

    free_test_context(test_ctx, 0 /* registered_translators*/, 0 /* not_accepted_translators */, 0 /* endpoints */);
    mock().checkExpectations();
    free(response_str);
    json_decref(request);
    json_decref(result);
}

TEST(protocol_api, test_get_certificate_internal_error_deeper)
{
    size_t binary_len = apr_base64_decode_len(cert_data_base64);
    unsigned char *cert_data_binary = (unsigned char *) calloc(1, binary_len);
    apr_base64_decode_binary(cert_data_binary, cert_data_base64);

    struct test_context *test_ctx = connection_initialized();
    test_registers_successfully(test_ctx);

    // Init rpc params object, one with missing and one with empty certificate field
    json_t *params = json_object();
    json_object_set_new(params, "certificate", json_string(certificate_name));

    // Build rpc request object
    json_t *request = json_object();
    json_object_set_new(request, "jsonrpc", json_string("2.0"));
    json_object_set_new(request, "id", json_string("1"));
    json_object_set_new(request, "method", json_string("crypto_get_certificate"));
    json_object_set_new(request, "params", params);

    char *data = json_dumps(request, JSON_COMPACT);
    struct json_message_t *userdata = alloc_json_message_t(data, strlen(data), test_ctx->connection);
    free(data);
    json_t *result = NULL;
    mock().expectOneCall("edgeclient_is_shutting_down").andReturnValue(false);
    mock().expectOneCall("eventOS_event_send")
            .withIntParameter("event_id", CRYPTO_API_EVENT_GET_CERTIFICATE)
            .withIntParameter("receiver", crypto_api_tasklet_id)
            .andReturnValue(0);
    int status = crypto_api_get_certificate(request, params, &result, userdata);
    CHECK_EQUAL(-1, status);
    mock().expectOneCall("kcm_item_get_data_size")
            .withStringParameter("kcm_item_data", certificate_name)
            .withIntParameter("kcm_item_name_len", strlen(certificate_name))
            .withIntParameter("kcm_item_type", KCM_CERTIFICATE_ITEM)
            .withOutputParameterReturning("kcm_item_data_size_out", &binary_len, sizeof(size_t))
            .andReturnValue(KCM_STATUS_SUCCESS);
    binary_len = 0;
    mock().expectOneCall("kcm_item_get_data")
            .withStringParameter("kcm_item_data", certificate_name)
            .withIntParameter("kcm_item_name_len", strlen(certificate_name))
            .withIntParameter("kcm_item_type", KCM_CERTIFICATE_ITEM)
            .withOutputParameterReturning("kcm_item_data_out", cert_data_binary, binary_len)
            .withOutputParameterReturning("kcm_item_data_act_size_out", &binary_len, sizeof(size_t))
            .andReturnValue(KCM_STATUS_UNKNOWN_STORAGE_ERROR);
    mock().expectOneCall("lws_callback_on_writable").andReturnValue(1);
    const char *expected_data = "{\"error\":{\"code\":-30000,\"data\":\"Got error when reading item from KCM, error "
                                "17 (KCM_STATUS_UNKNOWN_STORAGE_ERROR)\",\"message\":\"Protocol translator API "
                                "internal error.\"},\"id\":\"1\",\"jsonrpc\":\"2.0\"}";
    MyJsonFrame frame = MyJsonFrame(expected_data);
    MyJsonFrameComparator comparator;
    mock().installComparator("MyJsonFrame", comparator);

    expect_event_message_without_get_base(g_program_context->ev_base, safe_response_callback, true /* succeeds */);
    CHECK_EQUAL(true, eventOS_mock_event_handle());
    mock().expectOneCall("lws_write").withParameterOfType("MyJsonFrame", "buf", (const void *) &frame);
    evbase_mock_call_assigned_event_cb(g_program_context->ev_base, true);

    check_connection_free_expectations(test_ctx->connection, 26241, 0, 0 /* endpoints */);
    free_test_context(test_ctx, 1 /* registered_translators*/, 0 /* not_accepted_translators */, 0 /* endpoints */);

    mock().checkExpectations();
    deallocate_json_message_t(userdata);
    free(cert_data_binary);
    json_decref(request);
}

TEST(protocol_api, test_get_certificate_no_certificate_name)
{
    struct test_context *test_ctx = protocol_translator_registered(0);

    // Init rpc params object, one with missing and one with empty certificate field
    json_t *params = json_object();

    // Build rpc request object
    json_t *request = json_object();
    json_object_set_new(request, "jsonrpc", json_string("2.0"));
    json_object_set_new(request, "id", json_string("1"));
    json_object_set_new(request, "method", json_string("crypto_get_certificate"));
    json_object_set_new(request, "params", params);

    char *data = json_dumps(request, JSON_COMPACT);
    struct json_message_t *userdata = alloc_json_message_t(data, strlen(data), test_ctx->connection);
    free(data);
    json_t *result = NULL;
    mock().expectOneCall("edgeclient_is_shutting_down").andReturnValue(false);
    int status = crypto_api_get_certificate(request, params, &result, userdata);
    CHECK_EQUAL(1, status);
    char *response_str = json_dumps(result, JSON_COMPACT);
    STRCMP_EQUAL("{\"code\":-32602,\"message\":\"Invalid params\",\"data\":\"Get certificate failed. Missing or empty "
                 "certificate field.\"}",
                 response_str);

    check_connection_free_expectations(test_ctx->connection, 26241, 0, 0 /* endpoints */);
    deallocate_json_message_t(userdata);

    free_test_context(test_ctx, 0 /* registered_translators*/, 0 /* not_accepted_translators */, 0 /* endpoints */);
    mock().checkExpectations();
    json_decref(request);
    json_decref(result);
    free(response_str);
}

TEST(protocol_api, test_get_certificate_no_id)
{
    struct test_context *test_ctx = protocol_translator_registered(0);

    // Init rpc params object, one with missing and one with empty certificate field
    json_t *params = json_object();
    json_object_set_new(params, "certificate", json_string(certificate_name));

    // Build rpc request object
    json_t *request = json_object();
    json_object_set_new(request, "jsonrpc", json_string("2.0"));
    json_object_set_new(request, "method", json_string("crypto_get_certificate"));
    json_object_set_new(request, "params", params);

    char *data = json_dumps(request, JSON_COMPACT);
    struct json_message_t *userdata = alloc_json_message_t(data, strlen(data), test_ctx->connection);
    free(data);
    json_t *result = NULL;
    mock().expectOneCall("edgeclient_is_shutting_down").andReturnValue(false);
    int status = crypto_api_get_certificate(request, params, &result, userdata);
    CHECK_EQUAL(1, status);
    char *response_str = json_dumps(result, JSON_COMPACT);
    STRCMP_EQUAL("{\"code\":-32602,\"message\":\"Invalid params\",\"data\":\"Get certificate failed. No request id was "
                 "given.\"}",
                 response_str);

    check_connection_free_expectations(test_ctx->connection, 26241, 0, 0 /* endpoints */);
    deallocate_json_message_t(userdata);

    free_test_context(test_ctx, 0 /* registered_translators*/, 0 /* not_accepted_translators */, 0 /* endpoints */);
    mock().checkExpectations();
    json_decref(request);
    json_decref(result);
    free(response_str);
}

TEST(protocol_api, test_get_certificate_not_found)
{
    struct test_context *test_ctx = connection_initialized();
    test_registers_successfully(test_ctx);

    size_t binary_len = 0;

    // Init rpc params object, one with missing and one with empty certificate field
    json_t *params = json_object();
    json_object_set_new(params, "certificate", json_string(certificate_name));

    // Build rpc request object
    json_t *request = json_object();
    json_object_set_new(request, "jsonrpc", json_string("2.0"));
    json_object_set_new(request, "id", json_string("1"));
    json_object_set_new(request, "method", json_string("crypto_get_certificate"));
    json_object_set_new(request, "params", params);

    char *data = json_dumps(request, JSON_COMPACT);
    struct json_message_t *userdata = alloc_json_message_t(data, strlen(data), test_ctx->connection);
    free(data);
    json_t *result = NULL;
    mock().expectOneCall("edgeclient_is_shutting_down").andReturnValue(false);
    mock().expectOneCall("eventOS_event_send")
            .withIntParameter("event_id", CRYPTO_API_EVENT_GET_CERTIFICATE)
            .withIntParameter("receiver", crypto_api_tasklet_id)
            .andReturnValue(0);
    int status = crypto_api_get_certificate(request, params, &result, userdata);
    CHECK_EQUAL(-1, status);
    mock().expectOneCall("kcm_item_get_data_size")
            .withStringParameter("kcm_item_data", certificate_name)
            .withIntParameter("kcm_item_name_len", strlen(certificate_name))
            .withIntParameter("kcm_item_type", KCM_CERTIFICATE_ITEM)
            .withOutputParameterReturning("kcm_item_data_size_out", &binary_len, sizeof(size_t))
            .andReturnValue(KCM_STATUS_ITEM_NOT_FOUND);
    mock().expectOneCall("lws_callback_on_writable").andReturnValue(1);
    char *expected_data = NULL;
    asprintf(&expected_data,
             "{\"error\":{\"code\":-30000,\"data\":\"Got error when reading item size from KCM, error "
             "5 (KCM_STATUS_ITEM_NOT_FOUND)\",\"message\":\"Protocol translator API internal "
             "error.\"},\"id\":\"1\",\"jsonrpc\":\"2.0\"}");
    MyJsonFrame frame = MyJsonFrame(expected_data);
    MyJsonFrameComparator comparator;
    mock().installComparator("MyJsonFrame", comparator);

    expect_event_message_without_get_base(g_program_context->ev_base, safe_response_callback, true /* succeeds */);
    CHECK_EQUAL(true, eventOS_mock_event_handle());
    mock().expectOneCall("lws_write").withParameterOfType("MyJsonFrame", "buf", (const void *) &frame);
    evbase_mock_call_assigned_event_cb(g_program_context->ev_base, true);

    check_connection_free_expectations(test_ctx->connection, 26241, 0, 0 /* endpoints */);
    free_test_context(test_ctx, 1 /* registered_translators*/, 0 /* not_accepted_translators */, 0 /* endpoints */);

    mock().checkExpectations();
    deallocate_json_message_t(userdata);
    free(expected_data);
    json_decref(request);
}

TEST(protocol_api, test_get_public_key_exists)
{
    const char *key_name = "test-key";
    const char *key_data_base64 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEpL+tcY0fP6BdaKodmVlkM3xRnBU17az9QVGln+hcFa/B/"
                                  "c2p9kxNbX4xfM+KtbkAttJ6KwuOGDPMQIoT6aX5+A==";

    size_t binary_len = apr_base64_decode_len(key_data_base64);
    unsigned char *key_data_binary = (unsigned char *) calloc(1, binary_len);
    apr_base64_decode_binary(key_data_binary, key_data_base64);

    struct test_context *test_ctx = connection_initialized();
    test_registers_successfully(test_ctx);

    // Init rpc params object, one with missing and one with empty key field
    json_t *params = json_object();
    json_object_set_new(params, "key", json_string("test-key"));

    // Build rpc request object
    json_t *request = json_object();
    json_object_set_new(request, "jsonrpc", json_string("2.0"));
    json_object_set_new(request, "id", json_string("1"));
    json_object_set_new(request, "method", json_string("crypto_get_public_key"));
    json_object_set_new(request, "params", params);

    char *data = json_dumps(request, JSON_COMPACT);
    struct json_message_t *userdata = alloc_json_message_t(data, strlen(data), test_ctx->connection);
    free(data);
    json_t *result = NULL;
    mock().expectOneCall("edgeclient_is_shutting_down").andReturnValue(false);
    mock().expectOneCall("eventOS_event_send")
            .withIntParameter("event_id", CRYPTO_API_EVENT_GET_PUBLIC_KEY)
            .withIntParameter("receiver", crypto_api_tasklet_id)
            .andReturnValue(0);
    int status = crypto_api_get_public_key(request, params, &result, userdata);
    CHECK_EQUAL(-1, status);
    mock().expectOneCall("kcm_item_get_data_size")
            .withStringParameter("kcm_item_data", key_name)
            .withIntParameter("kcm_item_name_len", strlen(key_name))
            .withIntParameter("kcm_item_type", KCM_PUBLIC_KEY_ITEM)
            .withOutputParameterReturning("kcm_item_data_size_out", &binary_len, sizeof(size_t))
            .andReturnValue(KCM_STATUS_SUCCESS);
    mock().expectOneCall("kcm_item_get_data")
            .withStringParameter("kcm_item_data", key_name)
            .withIntParameter("kcm_item_name_len", strlen(key_name))
            .withIntParameter("kcm_item_type", KCM_PUBLIC_KEY_ITEM)
            .withOutputParameterReturning("kcm_item_data_out", key_data_binary, binary_len)
            .withOutputParameterReturning("kcm_item_data_act_size_out", &binary_len, sizeof(size_t))
            .andReturnValue(KCM_STATUS_SUCCESS);
    mock().expectOneCall("lws_callback_on_writable").andReturnValue(1);
    char *expected_data = NULL;
    asprintf(&expected_data,
             "{\"id\":\"1\",\"jsonrpc\":\"2.0\",\"result\":{\"key_data\":\"%s\",\"key_name\":\"%s\"}}",
             key_data_base64,
             key_name);
    MyJsonFrame frame = MyJsonFrame(expected_data);
    MyJsonFrameComparator comparator;
    mock().installComparator("MyJsonFrame", comparator);

    expect_event_message_without_get_base(g_program_context->ev_base, safe_response_callback, true /* succeeds */);
    CHECK_EQUAL(true, eventOS_mock_event_handle());
    mock().expectOneCall("lws_write").withParameterOfType("MyJsonFrame", "buf", (const void *) &frame);
    evbase_mock_call_assigned_event_cb(g_program_context->ev_base, true);

    check_connection_free_expectations(test_ctx->connection, 26241, 0, 0 /* endpoints */);
    free_test_context(test_ctx, 1 /* registered_translators*/, 0 /* not_accepted_translators */, 0 /* endpoints */);
    mock().checkExpectations();

    deallocate_json_message_t(userdata);
    free(key_data_binary);
    free(expected_data);
    json_decref(request);
}

TEST(protocol_api, test_get_public_key_internal_error)
{
    const char *key_data_base64 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEpL+tcY0fP6BdaKodmVlkM3xRnBU17az9QVGln+hcFa/B/"
                                  "c2p9kxNbX4xfM+KtbkAttJ6KwuOGDPMQIoT6aX5+A==";

    size_t binary_len = apr_base64_decode_len(key_data_base64);
    unsigned char *key_data_binary = (unsigned char *) calloc(1, binary_len);
    apr_base64_decode_binary(key_data_binary, key_data_base64);

    struct test_context *test_ctx = protocol_translator_registered(0);

    // Init rpc params object, one with missing and one with empty key field
    json_t *params = json_object();
    json_object_set_new(params, "key", json_string("test-key"));

    // Build rpc request object
    json_t *request = json_object();
    json_object_set_new(request, "jsonrpc", json_string("2.0"));
    json_object_set_new(request, "id", json_string("1"));
    json_object_set_new(request, "method", json_string("crypto_get_public_key"));
    json_object_set_new(request, "params", params);

    char *data = json_dumps(request, JSON_COMPACT);
    struct json_message_t *userdata = alloc_json_message_t(data, strlen(data), test_ctx->connection);
    free(data);
    json_t *result = NULL;
    mock().expectOneCall("edgeclient_is_shutting_down").andReturnValue(false);
    mock().expectOneCall("eventOS_event_send")
            .withIntParameter("event_id", CRYPTO_API_EVENT_GET_PUBLIC_KEY)
            .withIntParameter("receiver", crypto_api_tasklet_id)
            .andReturnValue(1);

    int status = crypto_api_get_public_key(request, params, &result, userdata);
    CHECK_EQUAL(1, status);
    char *response_str = json_dumps(result, JSON_COMPACT);
    STRCMP_EQUAL("{\"code\":-30000,\"message\":\"Protocol translator API internal error.\",\"data\":\"Could not send "
                 "crypto API event.\"}",
                 response_str);

    check_connection_free_expectations(test_ctx->connection, 26241, 0, 0 /* endpoints */);
    deallocate_json_message_t(userdata);

    free_test_context(test_ctx, 0 /* registered_translators*/, 0 /* not_accepted_translators */, 0 /* endpoints */);
    mock().checkExpectations();
    free(key_data_binary);
    json_decref(result);
    free(response_str);
    json_decref(request);
}

TEST(protocol_api, test_get_public_key_invalid_params)
{
    struct test_context *test_ctx = protocol_translator_registered(0);

    // Init rpc params object, one with missing and one with empty key field
    json_t *params = json_object();

    // Build rpc request object
    json_t *request = json_object();
    json_object_set_new(request, "jsonrpc", json_string("2.0"));
    json_object_set_new(request, "id", json_string("1"));
    json_object_set_new(request, "method", json_string("crypto_get_public_key"));
    json_object_set_new(request, "params", params);

    char *data = json_dumps(request, JSON_COMPACT);
    struct json_message_t *userdata = alloc_json_message_t(data, strlen(data), test_ctx->connection);
    free(data);
    json_t *result = NULL;
    mock().expectOneCall("edgeclient_is_shutting_down").andReturnValue(false);
    int status = crypto_api_get_public_key(request, params, &result, userdata);
    CHECK_EQUAL(1, status);
    char *response_str = json_dumps(result, JSON_COMPACT);
    STRCMP_EQUAL("{\"code\":-32602,\"message\":\"Invalid params\",\"data\":\"Get public key failed. Missing or empty "
                 "key field.\"}",
                 response_str);

    check_connection_free_expectations(test_ctx->connection, 26241, 0, 0 /* endpoints */);
    deallocate_json_message_t(userdata);

    free_test_context(test_ctx, 0 /* registered_translators*/, 0 /* not_accepted_translators */, 0 /* endpoints */);
    mock().checkExpectations();
    free(response_str);
    json_decref(result);
    json_decref(request);
}

TEST(protocol_api, test_get_public_key_no_request_id)
{
    struct test_context *test_ctx = protocol_translator_registered(0);
    // Init rpc params object, one with missing and one with empty key field
    json_t *params = json_object();

    // Build rpc request object
    json_t *request = json_object();
    json_object_set_new(request, "jsonrpc", json_string("2.0"));
    json_object_set_new(request, "method", json_string("crypto_get_public_key"));
    json_object_set_new(request, "params", params);

    char *data = json_dumps(request, JSON_COMPACT);
    struct json_message_t *userdata = alloc_json_message_t(data, strlen(data), test_ctx->connection);
    free(data);
    json_t *result = NULL;
    mock().expectOneCall("edgeclient_is_shutting_down").andReturnValue(false);
    int status = crypto_api_get_public_key(request, params, &result, userdata);
    CHECK_EQUAL(1, status);
    char *response_str = json_dumps(result, JSON_COMPACT);
    STRCMP_EQUAL("{\"code\":-32602,\"message\":\"Invalid params\",\"data\":\"Get public key failed. No request id was "
                 "given.\"}",
                 response_str);

    check_connection_free_expectations(test_ctx->connection, 26241, 0, 0 /* endpoints */);
    deallocate_json_message_t(userdata);

    free_test_context(test_ctx, 0 /* registered_translators*/, 0 /* not_accepted_translators */, 0 /* endpoints */);
    mock().checkExpectations();
    free(response_str);
    json_decref(request);
    json_decref(result);
}

static struct json_message_t *create_endpoint_with_expectations(struct connection *connection,
                                                                const char *endpoint_json_filepath,
                                                                int expected_rc,
                                                                const char *expected_json_string)
{
    // Load device registration jsonrpc parameters structure from file
    json_t *params = load_json_params(endpoint_json_filepath);

    // Build device registration jsonrpc structure
    json_t *request = json_object();
    json_object_set_new(request, "jsonrpc", json_string("2.0"));
    json_object_set_new(request, "id", json_string("1"));
    json_object_set_new(request, "method", json_string("device_register"));
    json_object_set_new(request, "params", params);

    char *data = json_dumps(request, JSON_COMPACT);
    struct json_message_t *userdata = alloc_json_message_t(data, strlen(data), connection);
    free(data);

    json_t *result;
    int32_t old_count = edgeserver_get_number_registered_endpoints_count();
    int rc = device_register(request, params, &result, userdata);
    int32_t new_count = edgeserver_get_number_registered_endpoints_count();
    CHECK_EQUAL(expected_rc, rc);
    if (expected_rc == 0) {
        CHECK(new_count == old_count + 1);
    } else {
        CHECK(new_count == old_count);
    }

    CHECK(result != NULL);
    if (rc == 0) {
        STRCMP_EQUAL(expected_json_string, json_string_value(result));
    } else {
        json_error_t error;
        char *result_str = json_dumps(result, JSON_COMPACT | JSON_SORT_KEYS );
        json_t *expected_json = json_loads(expected_json_string, 0, &error);
        char *expected_sorted_str = json_dumps(expected_json, JSON_COMPACT | JSON_SORT_KEYS);
        STRCMP_EQUAL(expected_sorted_str, result_str);
        json_decref(expected_json);
        free(expected_sorted_str);
        free(result_str);
    }

    json_decref(request);
    json_decref(result);
    return userdata;
}

static struct json_message_t *create_endpoint(struct connection *connection, const char *endpoint_json_filepath)
{
    return create_endpoint_with_expectations(connection, endpoint_json_filepath, 0, "ok");
}

static struct test_context* create_test_context(struct context *context)
{
    struct test_context *test_ctx = (struct test_context*)calloc(1, sizeof(struct test_context));
    test_ctx->context = context;
    return test_ctx;
}

struct test_context* connection_initialized()
{
    struct ctx_data *ctx_data = (struct ctx_data *) g_program_context->ctx_data;
    ns_list_init(&ctx_data->registered_translators);
    struct test_context *test_ctx = create_test_context(g_program_context);
    mock().expectOneCall("lws_hdr_total_length")
        .withIntParameter("h", (int) WSI_TOKEN_GET_URI)
        .andReturnValue((int) strlen("/1/pt"));
    mock().expectOneCall("lws_hdr_copy")
        .withOutputParameterReturning("dest", "/1/pt", strlen("/1/pt"))
        .ignoreOtherParameters()
        .andReturnValue(1);
    test_ctx->connection = server_test_establish_connection();
    CHECK_EQUAL(0, edgeserver_get_number_registered_endpoints_count());
    return test_ctx;
}

static void free_test_context(struct test_context *test_context,
                              int32_t expected_registered,
                              int32_t expected_not_accepted,
                              int32_t registered_endpoints)
{
    check_context(test_context->context, expected_registered, expected_not_accepted, registered_endpoints);
    if (test_context->connection) {
        server_test_free_established_connection(test_context->connection);
        free_transport_connection(test_context->connection->transport_connection);
        CHECK_EQUAL((int32_t) registered_endpoints, (int32_t) connection_free(test_context->connection));
        edgeserver_change_number_registered_endpoints_by_delta(-registered_endpoints);
    }
    free(test_context);
}

static void free_transport_connection(struct transport_connection *transport_connection)
{
    free(transport_connection);
}

struct test_context* protocol_translator_registered(int id)
{
    struct test_context *test_ctx = connection_initialized();
    test_ctx->connection->client_data->registered = true;
    test_ctx->connection->client_data->id = id;
    return test_ctx;
}

struct test_context* protocol_translator_not_registered()
{
    struct test_context *test_ctx = connection_initialized();
    test_ctx->connection->client_data->registered = false;
    test_ctx->connection->client_data->id = -1;
    return test_ctx;
}

static void check_context(struct context *context,
                          int32_t expected_registered,
                          int32_t expected_not_accepted,
                          int32_t registered_endpoints)
{
    struct ctx_data *ctx_data = (struct ctx_data *)context->ctx_data;
    CHECK_EQUAL(registered_endpoints, edgeserver_get_number_registered_endpoints_count());
    CHECK_EQUAL(expected_registered, free_all_translators(&ctx_data->registered_translators));
    CHECK_EQUAL(expected_not_accepted, free_all_translators(&ctx_data->not_accepted_translators));
}

static void check_remove_resources_and_objects_owned_by_client(struct connection *connection, uint32_t total_endpoints)
{
    mock().expectOneCall("remove_resources_owned_by_client")
            .withPointerParameter("client_context", (void *) (connection))
            .andReturnValue(0);

    mock().expectOneCall("remove_objects_owned_by_client")
            .withPointerParameter("client_context", (void *) (connection))
            .andReturnValue(total_endpoints);
}

TEST_GROUP(error_parser){void setup(){} void teardown(){}};

TEST(error_parser, test_pt_api_parser_error_response_no_error)
{
    edgeclient_request_context_t *ctx = (edgeclient_request_context_t *) calloc(1,
                                                                                sizeof(edgeclient_request_context_t));
    char *response = strdup("{\"id\":\"1\",\"jsonrpc\":\"2.0\"}");

    json_error_t error;
    json_t *json_response = json_loads(response, 0, &error);
    pt_api_error_parser_parse_error_response(json_response, ctx);
    free(ctx);
    json_decref(json_response);
    free(response);
}

TEST(error_parser, test_pt_api_parser_error_response_no_code)
{
    edgeclient_request_context_t *ctx = (edgeclient_request_context_t *) calloc(1,
                                                                                sizeof(edgeclient_request_context_t));
    char *response = strdup("{\"id\":\"1\",\"jsonrpc\":\"2.0\",\"error\":{\"data\":\"Request "
                            "timeout\",\"message\": \"Timeout response with timeout threshold 60000 ms\"}}");

    json_error_t error;
    json_t *json_response = json_loads(response, 0, &error);
    pt_api_error_parser_parse_error_response(json_response, ctx);
    free(ctx);
    json_decref(json_response);
    free(response);
}


const unsigned char randombytes[] = {
    0x08, 0x7d, 0xb3, 0x9f, 0x16, 0x61, 0xb5, 0xaa, 0xb5, 0x89, 0xb3, 0x4d,
    0xc3, 0x47, 0x60, 0x9c, 0xda, 0x66, 0x8e, 0xed, 0x30, 0x92, 0xa7, 0x15,
    0x17, 0xf0, 0x7c, 0x40, 0x8e, 0x2b, 0x20, 0xb5, 0xf6, 0x47, 0x0f, 0x4f,
    0x73, 0x3e, 0xa1, 0xe4, 0x92, 0x4e, 0x19, 0x61, 0x43, 0xcd, 0x65, 0x97,
    0xd7, 0x84, 0x49, 0x52, 0x81, 0xfe, 0xfe, 0x49, 0x8a, 0x55, 0x14, 0x11,
    0xcb, 0x95, 0x31, 0x88, 0x3d, 0xaa, 0x61, 0xcf, 0xef, 0x15, 0x89, 0x1e,
    0xc1, 0xa7, 0x84, 0xd6, 0x84, 0x91, 0x11, 0x68, 0x58, 0x82, 0x39, 0xd6,
    0xb3, 0x23, 0x61, 0x89, 0x12, 0x28, 0xfa, 0xbc, 0xcb, 0x38, 0xe4, 0x90,
    0x13, 0xf6, 0x2c, 0x51, 0x66, 0x0d, 0xdd, 0xcc, 0x1b, 0x83, 0x17, 0xdc,
    0x3b, 0x08, 0xb5, 0x4f, 0xc1, 0x4f, 0xa7, 0xcf, 0x52, 0x8f, 0xfa, 0xa0,
    0x7f, 0xee, 0xfe, 0x15, 0x6f, 0xea, 0x75, 0x0c
};
const unsigned int randombytes_len = 128;
const char *randombytes_base64 = "CH2znxZhtaq1ibNNw0dgnNpmju0wkqcVF/B8QI4rILX2Rw9Pcz6h5JJOGWFDzWWX14RJUoH+/kmKVRQRy5UxiD2qYc/vFYkewaeE1oSREWhYgjnWsyNhiRIo+rzLOOSQE/YsUWYN3cwbgxfcOwi1T8FPp89Sj/qgf+7+FW/qdQw=";

TEST(protocol_api, test_generate_random_success)
{
    struct test_context *test_ctx = connection_initialized();
    test_registers_successfully(test_ctx);

    // Init rpc params object, one with missing and one with empty key field
    json_t *params = json_object();
    json_object_set_new(params, "size", json_integer(128));

    // Build rpc request object
    json_t *request = json_object();
    json_object_set_new(request, "jsonrpc", json_string("2.0"));
    json_object_set_new(request, "id", json_string("1"));
    json_object_set_new(request, "method", json_string("crypto_generate_random"));
    json_object_set_new(request, "params", params);

    char *data = json_dumps(request, JSON_COMPACT);
    struct json_message_t *userdata = alloc_json_message_t(data, strlen(data), test_ctx->connection);
    free(data);
    json_t *result = NULL;
    mock().expectOneCall("edgeclient_is_shutting_down").andReturnValue(false);
    mock().expectOneCall("eventOS_event_send")
            .withIntParameter("event_id", CRYPTO_API_EVENT_GENERATE_RANDOM)
            .withIntParameter("receiver", crypto_api_tasklet_id)
            .andReturnValue(0);
    int status = crypto_api_generate_random(request, params, &result, userdata);
    CHECK_EQUAL(-1, status);

    mock().expectOneCall("kcm_generate_random")
        .withOutputParameterReturning("buffer", randombytes, randombytes_len)
        .withUnsignedIntParameter("buffer_size", randombytes_len)
        .andReturnValue(KCM_STATUS_SUCCESS);
    mock().expectOneCall("lws_callback_on_writable").andReturnValue(1);
    char *expected_data = NULL;
    asprintf(&expected_data,
             "{\"id\":\"1\",\"jsonrpc\":\"2.0\",\"result\":{\"data\":\"%s\"}}",
             randombytes_base64);
    MyJsonFrame frame = MyJsonFrame(expected_data);
    MyJsonFrameComparator comparator;
    mock().installComparator("MyJsonFrame", comparator);

    expect_event_message_without_get_base(g_program_context->ev_base, safe_response_callback, true /* succeeds */);
    CHECK_EQUAL(true, eventOS_mock_event_handle());
    mock().expectOneCall("lws_write").withParameterOfType("MyJsonFrame", "buf", (const void *) &frame);
    evbase_mock_call_assigned_event_cb(g_program_context->ev_base, true);

    check_connection_free_expectations(test_ctx->connection, 26241, 0, 0 /* endpoints */);
    free_test_context(test_ctx, 1 /* registered_translators*/, 0 /* not_accepted_translators */, 0 /* endpoints */);
    mock().checkExpectations();

    deallocate_json_message_t(userdata);
    json_decref(request);
    free(expected_data);
}

TEST(protocol_api, test_generate_random_failure)
{
    struct test_context *test_ctx = connection_initialized();
    test_registers_successfully(test_ctx);

    // Init rpc params object, one with missing and one with empty key field
    json_t *params = json_object();
    json_object_set_new(params, "size", json_integer(128));

    // Build rpc request object
    json_t *request = json_object();
    json_object_set_new(request, "jsonrpc", json_string("2.0"));
    json_object_set_new(request, "id", json_string("1"));
    json_object_set_new(request, "method", json_string("crypto_generate_random"));
    json_object_set_new(request, "params", params);

    char *data = json_dumps(request, JSON_COMPACT);
    struct json_message_t *userdata = alloc_json_message_t(data, strlen(data), test_ctx->connection);
    free(data);
    json_t *result = NULL;
    mock().expectOneCall("edgeclient_is_shutting_down").andReturnValue(false);
    mock().expectOneCall("eventOS_event_send")
            .withIntParameter("event_id", CRYPTO_API_EVENT_GENERATE_RANDOM)
            .withIntParameter("receiver", crypto_api_tasklet_id)
            .andReturnValue(0);
    int status = crypto_api_generate_random(request, params, &result, userdata);
    CHECK_EQUAL(-1, status);

    mock().expectOneCall("kcm_generate_random")
        .withOutputParameterReturning("buffer", randombytes, randombytes_len)
        .withUnsignedIntParameter("buffer_size", randombytes_len)
        .andReturnValue(KCM_CRYPTO_STATUS_ENTROPY_MISSING);
    mock().expectOneCall("lws_callback_on_writable").andReturnValue(1);
    char *expected_data = NULL;
    asprintf(&expected_data,
             "{\"id\":\"1\",\"jsonrpc\":\"2.0\","
             "\"error\":{\"code\":-30000,\"data\":\"Got error when generating random, error "
             "%d (KCM_CRYPTO_STATUS_ENTROPY_MISSING)\",\"message\":\"Protocol translator API internal "
             "error.\"}}", KCM_CRYPTO_STATUS_ENTROPY_MISSING);
    MyJsonFrame frame = MyJsonFrame(expected_data);
    MyJsonFrameComparator comparator;
    mock().installComparator("MyJsonFrame", comparator);

    expect_event_message_without_get_base(g_program_context->ev_base, safe_response_callback, true /* succeeds */);
    CHECK_EQUAL(true, eventOS_mock_event_handle());
    mock().expectOneCall("lws_write").withParameterOfType("MyJsonFrame", "buf", (const void *) &frame);
    evbase_mock_call_assigned_event_cb(g_program_context->ev_base, true);

    check_connection_free_expectations(test_ctx->connection, 26241, 0, 0 /* endpoints */);
    free_test_context(test_ctx, 1 /* registered_translators*/, 0 /* not_accepted_translators */, 0 /* endpoints */);
    mock().checkExpectations();

    deallocate_json_message_t(userdata);
    json_decref(request);
    free(expected_data);
}

TEST(protocol_api, test_generate_random_invalid_params)
{
    struct test_context *test_ctx = connection_initialized();
    test_registers_successfully(test_ctx);

    // Init rpc params object, one with missing and one with empty key field
    json_t *params = json_object();

    // Build rpc request object
    json_t *request = json_object();
    json_object_set_new(request, "jsonrpc", json_string("2.0"));
    json_object_set_new(request, "id", json_string("1"));
    json_object_set_new(request, "method", json_string("crypto_generate_random"));
    json_object_set_new(request, "params", params);

    char *data = json_dumps(request, JSON_COMPACT);
    struct json_message_t *userdata = alloc_json_message_t(data, strlen(data), test_ctx->connection);
    free(data);
    json_t *result = NULL;
    mock().expectOneCall("edgeclient_is_shutting_down").andReturnValue(false);
    int status = crypto_api_generate_random(request, params, &result, userdata);
    CHECK_EQUAL(1, status);
    char *response_str = json_dumps(result, JSON_COMPACT);
    STRCMP_EQUAL("{\"code\":-32602,\"message\":\"Invalid params\",\"data\":\"Generate random failed. Missing or invalid "
                 "size field.\"}",
                 response_str);
    json_decref(result);
    free(response_str);

    result = NULL;
    mock().expectOneCall("edgeclient_is_shutting_down").andReturnValue(false);
    // With zero size field
    json_object_set_new(params, "size", json_integer(0));

    status = crypto_api_generate_random(request, params, &result, userdata);
    CHECK_EQUAL(1, status);
    response_str = json_dumps(result, JSON_COMPACT);
    STRCMP_EQUAL("{\"code\":-32602,\"message\":\"Invalid params\",\"data\":\"Generate random failed. Missing or invalid "
                 "size field.\"}",
                 response_str);

    check_connection_free_expectations(test_ctx->connection, 26241, 0, 0 /* endpoints */);
    deallocate_json_message_t(userdata);

    free_test_context(test_ctx, 1 /* registered_translators*/, 0 /* not_accepted_translators */, 0 /* endpoints */);
    mock().checkExpectations();
    json_decref(request);
    json_decref(result);
    free(response_str);
}

TEST(protocol_api, test_generate_random_internal_error)
{
    struct test_context *test_ctx = connection_initialized();
    test_registers_successfully(test_ctx);

    // Init rpc params object, one with missing and one with empty key field
    json_t *params = json_object();
    json_object_set_new(params, "size", json_integer(128));

    // Build rpc request object
    json_t *request = json_object();
    json_object_set_new(request, "jsonrpc", json_string("2.0"));
    json_object_set_new(request, "id", json_string("1"));
    json_object_set_new(request, "method", json_string("crypto_generate_random"));
    json_object_set_new(request, "params", params);

    char *data = json_dumps(request, JSON_COMPACT);
    struct json_message_t *userdata = alloc_json_message_t(data, strlen(data), test_ctx->connection);
    free(data);
    json_t *result = NULL;
    mock().expectOneCall("edgeclient_is_shutting_down").andReturnValue(false);
    mock().expectOneCall("eventOS_event_send")
        .withIntParameter("event_id", CRYPTO_API_EVENT_GENERATE_RANDOM)
        .withIntParameter("receiver", crypto_api_tasklet_id)
        .andReturnValue(1);

    int status = crypto_api_generate_random(request, params, &result, userdata);
    CHECK_EQUAL(1, status);
    char *response_str = json_dumps(result, JSON_COMPACT);
    STRCMP_EQUAL("{\"code\":-30000,\"message\":\"Protocol translator API internal error.\",\"data\":\"Could not send "
                 "crypto API event.\"}",
                 response_str);

    check_connection_free_expectations(test_ctx->connection, 26241, 0, 0 /* endpoints */);
    deallocate_json_message_t(userdata);

    free_test_context(test_ctx, 1 /* registered_translators*/, 0 /* not_accepted_translators */, 0 /* endpoints */);
    mock().checkExpectations();
    json_decref(request);
    json_decref(result);
    free(response_str);
}

unsigned char hash[] = {
    0x71, 0x66, 0xa6, 0xf2, 0x44, 0x28, 0x3b, 0x24, 0xd4, 0x61, 0x17, 0x53,
    0xa2, 0xa3, 0xa1, 0x77, 0x1f, 0x64, 0x69, 0xa9, 0x0a, 0xd1, 0x0b, 0x65,
    0xea, 0x7a, 0xad, 0x23, 0xdf, 0xad, 0x3c, 0x7e
};
unsigned int hash_len = 32;
const char *hash_base64 = "cWam8kQoOyTUYRdToqOhdx9kaakK0Qtl6nqtI9+tPH4=";

unsigned char signaturebytes[] = {
    0x6e, 0x01, 0xd9, 0xcf, 0x4e, 0xe7, 0xfd, 0xcc, 0xfd, 0xd6, 0x0c, 0x52,
    0x7b, 0xf1, 0x04, 0x2c, 0xeb, 0x8f, 0x2e, 0xd1, 0x82, 0xbb, 0x07, 0xc4,
    0x3e, 0x36, 0x1e, 0xb5, 0x4a, 0x8a, 0x6b, 0x36, 0x0f, 0xba, 0x73, 0x0a,
    0x70, 0x23, 0x29, 0xfa, 0x5c, 0xb8, 0x0c, 0xee, 0x71, 0x15, 0xc3, 0xcb,
    0x3f, 0x3f, 0x25, 0xdc, 0xd2, 0x7e, 0x31, 0xc3, 0x35, 0xc9, 0x16, 0xdc,
    0xdf, 0x5e, 0x1b, 0x69
};
size_t signaturebytes_len = 64;
const char *signature_base64 = "bgHZz07n/cz91gxSe/EELOuPLtGCuwfEPjYetUqKazYPunMKcCMp+ly4DO5xFcPLPz8l3NJ+McM1yRbc314baQ==";

TEST(protocol_api, test_asymmetric_sign_success)
{
    const char *private_key_name = "dlms";

    struct test_context *test_ctx = connection_initialized();
    test_registers_successfully(test_ctx);

    // Init rpc params object, one with missing and one with empty key field
    json_t *params = json_object();
    json_object_set_new(params, "private_key_name", json_string(private_key_name));
    json_object_set_new(params, "hash_digest", json_string(hash_base64));

    // Build rpc request object
    json_t *request = json_object();
    json_object_set_new(request, "jsonrpc", json_string("2.0"));
    json_object_set_new(request, "id", json_string("1"));
    json_object_set_new(request, "method", json_string("crypto_asymmetric_sign"));
    json_object_set_new(request, "params", params);

    char *data = json_dumps(request, JSON_COMPACT);
    struct json_message_t *userdata = alloc_json_message_t(data, strlen(data), test_ctx->connection);
    free(data);
    json_t *result = NULL;
    mock().expectOneCall("edgeclient_is_shutting_down").andReturnValue(false);
    mock().expectOneCall("eventOS_event_send")
            .withIntParameter("event_id", CRYPTO_API_EVENT_ASYMMETRIC_SIGN)
            .withIntParameter("receiver", crypto_api_tasklet_id)
            .andReturnValue(0);
    int status = crypto_api_asymmetric_sign(request, params, &result, userdata);
    CHECK_EQUAL(-1, status);

    mock().expectOneCall("kcm_asymmetric_sign")
        .withMemoryBufferParameter("private_key_name", (const unsigned char*) private_key_name, strlen(private_key_name))
        .withMemoryBufferParameter("hash_digest", hash, hash_len)
        .withOutputParameterReturning("signature_data_out", signaturebytes, signaturebytes_len)
        .withUnsignedIntParameter("signature_data_max_size", KCM_EC_SECP256R1_SIGNATURE_RAW_SIZE)
        .withOutputParameterReturning("signature_data_act_size_out", &signaturebytes_len, sizeof(signaturebytes_len))
        .andReturnValue(KCM_STATUS_SUCCESS);
    mock().expectOneCall("lws_callback_on_writable").andReturnValue(1);
    char *expected_data = NULL;
    asprintf(&expected_data,
             "{\"id\":\"1\",\"jsonrpc\":\"2.0\",\"result\":{\"signature_data\":\"%s\"}}",
             signature_base64);
    MyJsonFrame frame = MyJsonFrame(expected_data);
    MyJsonFrameComparator comparator;
    mock().installComparator("MyJsonFrame", comparator);

    expect_event_message_without_get_base(g_program_context->ev_base, safe_response_callback, true /* succeeds */);
    CHECK_EQUAL(true, eventOS_mock_event_handle());
    mock().expectOneCall("lws_write").withParameterOfType("MyJsonFrame", "buf", (const void *) &frame);
    evbase_mock_call_assigned_event_cb(g_program_context->ev_base, true);

    check_connection_free_expectations(test_ctx->connection, 26241, 0, 0 /* endpoints */);
    free_test_context(test_ctx, 1 /* registered_translators*/, 0 /* not_accepted_translators */, 0 /* endpoints */);
    mock().checkExpectations();

    deallocate_json_message_t(userdata);
    json_decref(request);
    free(expected_data);
}

TEST(protocol_api, test_asymmetric_sign_failure)
{
    const char *private_key_name = "dlms";

    struct test_context *test_ctx = connection_initialized();
    test_registers_successfully(test_ctx);

    // Init rpc params object, one with missing and one with empty key field
    json_t *params = json_object();
    json_object_set_new(params, "private_key_name", json_string(private_key_name));
    json_object_set_new(params, "hash_digest", json_string(hash_base64));

    // Build rpc request object
    json_t *request = json_object();
    json_object_set_new(request, "jsonrpc", json_string("2.0"));
    json_object_set_new(request, "id", json_string("1"));
    json_object_set_new(request, "method", json_string("crypto_asymmetric_sign"));
    json_object_set_new(request, "params", params);

    char *data = json_dumps(request, JSON_COMPACT);
    struct json_message_t *userdata = alloc_json_message_t(data, strlen(data), test_ctx->connection);
    free(data);
    json_t *result = NULL;
    mock().expectOneCall("edgeclient_is_shutting_down").andReturnValue(false);
    mock().expectOneCall("eventOS_event_send")
            .withIntParameter("event_id", CRYPTO_API_EVENT_ASYMMETRIC_SIGN)
            .withIntParameter("receiver", crypto_api_tasklet_id)
            .andReturnValue(0);
    int status = crypto_api_asymmetric_sign(request, params, &result, userdata);
    CHECK_EQUAL(-1, status);

    mock().expectOneCall("kcm_asymmetric_sign")
        .withMemoryBufferParameter("private_key_name", (const unsigned char*) private_key_name, strlen(private_key_name))
        .withMemoryBufferParameter("hash_digest", hash, hash_len)
        .withOutputParameterReturning("signature_data_out", signaturebytes, signaturebytes_len)
        .withUnsignedIntParameter("signature_data_max_size", KCM_EC_SECP256R1_SIGNATURE_RAW_SIZE)
        .withOutputParameterReturning("signature_data_act_size_out", &signaturebytes_len, sizeof(signaturebytes_len))
        .andReturnValue(KCM_STATUS_ITEM_NOT_FOUND);
    mock().expectOneCall("lws_callback_on_writable").andReturnValue(1);
    char *expected_data = NULL;
    asprintf(&expected_data,
             "{\"id\":\"1\",\"jsonrpc\":\"2.0\","
             "\"error\":{\"code\":-30000,\"data\":\"Got error when signing, error "
             "%d (KCM_STATUS_ITEM_NOT_FOUND)\",\"message\":\"Protocol translator API internal "
             "error.\"}}", KCM_STATUS_ITEM_NOT_FOUND);
    MyJsonFrame frame = MyJsonFrame(expected_data);
    MyJsonFrameComparator comparator;
    mock().installComparator("MyJsonFrame", comparator);

    expect_event_message_without_get_base(g_program_context->ev_base, safe_response_callback, true /* succeeds */);
    CHECK_EQUAL(true, eventOS_mock_event_handle());
    mock().expectOneCall("lws_write").withParameterOfType("MyJsonFrame", "buf", (const void *) &frame);
    evbase_mock_call_assigned_event_cb(g_program_context->ev_base, true);

    check_connection_free_expectations(test_ctx->connection, 26241, 0, 0 /* endpoints */);
    free_test_context(test_ctx, 1 /* registered_translators*/, 0 /* not_accepted_translators */, 0 /* endpoints */);
    mock().checkExpectations();

    deallocate_json_message_t(userdata);
    json_decref(request);
    free(expected_data);
}

typedef struct {
    jsonrpc_method_prototype method_fn;
    const char *method_name;
    const char *error;
    const char *params;
    int event_id;
} crypto_test_params_t;

const char *asymmetric_sign_params_error = "Asymmetric sign failed. Missing or invalid private_key_name or hash_digest field.";
const char *asymmetric_verify_params_error = "Asymmetric verify failed. Missing or invalid public_key_name, hash_digest or signature field.";
const char *ecdh_params_error = "ECDH key agreement failed. Missing or invalid private_key_name or peer_public_key field.";
const crypto_test_params_t invalid_params_data[] = {
    { // Missing parameters
        .method_fn = crypto_api_asymmetric_sign,
        .method_name = "crypto_asymmetric_sign",
        .error = asymmetric_sign_params_error,
        .params = "{}"
    },
    { // Missing hash
        .method_fn = crypto_api_asymmetric_sign,
        .method_name = "crypto_asymmetric_sign",
        .error = asymmetric_sign_params_error,
        .params = "{\"private_key_name\":\"test\"}"
    },
    { // Missing private key
        .method_fn = crypto_api_asymmetric_sign,
        .method_name = "crypto_asymmetric_sign",
        .error = asymmetric_sign_params_error,
        .params = "{\"hash_digest\":\"dGVzdAo=\"}"
    },
    { // Missing parameters
        .method_fn = crypto_api_asymmetric_verify,
        .method_name = "crypto_asymmetric_verify",
        .error = asymmetric_verify_params_error,
        .params = "{}"
    },
    {// Missing public key
        .method_fn = crypto_api_asymmetric_verify,
        .method_name = "crypto_asymmetric_verify",
        .error = asymmetric_verify_params_error,
        .params = "{\"hash_digest\":\"test\", \"signature\":\"dGVzdAo=\"}"
    },
    { // missing hash
        .method_fn = crypto_api_asymmetric_verify,
        .method_name = "crypto_asymmetric_verify",
        .error = asymmetric_verify_params_error,
        .params = "{\"public_key_name\":\"test\", \"signature\":\"dGVzdAo=\"}"
    },
    { // Missing signature
        .method_fn = crypto_api_asymmetric_verify,
        .method_name = "crypto_asymmetric_verify",
        .error = asymmetric_verify_params_error,
        .params = "{\"public_key_name\":\"test\", \"hash_digest\":\"dGVzdAo=\"}"
    },
    { // Missing parameters
        .method_fn = crypto_api_ecdh_key_agreement,
        .method_name = "crypto_ecdh_key_agreement",
        .error = ecdh_params_error,
        .params = "{}"
    },
    { // Missing peer public key
        .method_fn = crypto_api_ecdh_key_agreement,
        .method_name = "crypto_ecdh_key_agreement",
        .error = ecdh_params_error,
        .params = "{\"private_key_name\":\"test\"}"
    },
    { // Missing private key
        .method_fn = crypto_api_ecdh_key_agreement,
        .method_name = "crypto_ecdh_key_agreement",
        .error = ecdh_params_error,
        .params = "{\"peer_public_key\":\"test\"}"
    },
    { // Missing private key
        .method_fn = crypto_api_ecdh_key_agreement,
        .method_name = "crypto_ecdh_key_agreement",
        .error = ecdh_params_error,
        .params = "{\"peer_public_key\":\"test\"}"
    }
};

TEST(protocol_api, test_crypto_methods_invalid_params)
{
    for (unsigned int i = 0; i < sizeof(invalid_params_data) / sizeof(crypto_test_params_t); i++) {
        struct test_context *test_ctx = connection_initialized();
        test_registers_successfully(test_ctx);

        // Init rpc params object, one with missing and one with empty key field
        json_t *params = json_loads(invalid_params_data[i].params, 0, NULL);

        // Build rpc request object
        json_t *request = json_object();
        json_object_set_new(request, "jsonrpc", json_string("2.0"));
        json_object_set_new(request, "id", json_string("1"));
        json_object_set_new(request, "method", json_string(invalid_params_data[i].method_name));
        json_object_set_new(request, "params", params);

        char *data = json_dumps(request, JSON_COMPACT);
        struct json_message_t *userdata = alloc_json_message_t(data, strlen(data), test_ctx->connection);
        free(data);
        json_t *result = NULL;
        mock().expectOneCall("edgeclient_is_shutting_down").andReturnValue(false);
        int status = invalid_params_data[i].method_fn(request, params, &result, userdata);
        CHECK_EQUAL(JSONRPC_RETURN_CODE_ERROR, status);
        char *response_str = json_dumps(result, JSON_COMPACT);
        char *expected_error = NULL;
        asprintf(&expected_error,
                 "{\"code\":-32602,\"message\":\"Invalid params\",\"data\":\"%s\"}",
                 invalid_params_data[i].error);
        STRCMP_EQUAL(expected_error,
                     response_str);
        free(response_str);
        free(expected_error);
        json_decref(result);

        check_connection_free_expectations(test_ctx->connection, 26241, 0, 0 /* endpoints */);
        free_test_context(test_ctx, 1 /* registered_translators*/, 0 /* not_accepted_translators */, 0 /* endpoints */);
        mock().checkExpectations();

        deallocate_json_message_t(userdata);
        json_decref(request);
    }
}

const crypto_test_params_t valid_params_data[] = {
    {
        .method_fn = crypto_api_asymmetric_sign,
        .method_name = "crypto_asymmetric_sign",
        .error = NULL,
        .params = "{\"private_key_name\":\"test\", \"hash_digest\":\"dGVzdAo=\"}",
        .event_id = CRYPTO_API_EVENT_ASYMMETRIC_SIGN
    },
    {
        .method_fn = crypto_api_asymmetric_verify,
        .method_name = "crypto_asymmetric_verify",
        .error = NULL,
        .params = "{\"public_key_name\":\"test\", \"hash_digest\":\"dGVzdAo=\", \"signature\":\"dGVzdAo=\"}",
        .event_id = CRYPTO_API_EVENT_ASYMMETRIC_VERIFY
    },
    { // Missing peer public key
        .method_fn = crypto_api_ecdh_key_agreement,
        .method_name = "crypto_ecdh_key_agreement",
        .error = NULL,
        .params = "{\"private_key_name\":\"test\", \"peer_public_key\":\"dGVzdAo=\"}",
        .event_id = CRYPTO_API_EVENT_ECDH_KEY_AGREEMENT
    }
};

TEST(protocol_api, test_crypto_methods_event_send_fails)
{
    for (unsigned int i = 0; i < sizeof(valid_params_data) / sizeof(crypto_test_params_t); i++) {
        struct test_context *test_ctx = connection_initialized();
        test_registers_successfully(test_ctx);

        // Init rpc params object, one with missing and one with empty key field
        json_t *params = json_loads(valid_params_data[i].params, 0, NULL);

        // Build rpc request object
        json_t *request = json_object();
        json_object_set_new(request, "jsonrpc", json_string("2.0"));
        json_object_set_new(request, "id", json_string("1"));
        json_object_set_new(request, "method", json_string(valid_params_data[i].method_name));
        json_object_set_new(request, "params", params);

        char *data = json_dumps(request, JSON_COMPACT);
        struct json_message_t *userdata = alloc_json_message_t(data, strlen(data), test_ctx->connection);
        free(data);
        json_t *result = NULL;
        mock().expectOneCall("edgeclient_is_shutting_down").andReturnValue(false);
        mock().expectOneCall("eventOS_event_send")
            .withIntParameter("event_id", valid_params_data[i].event_id)
            .withIntParameter("receiver", crypto_api_tasklet_id)
            .andReturnValue(1);
        int status = valid_params_data[i].method_fn(request, params, &result, userdata);
        CHECK_EQUAL(JSONRPC_RETURN_CODE_ERROR, status);
        char *response_str = json_dumps(result, JSON_COMPACT);
        STRCMP_EQUAL("{\"code\":-30000,\"message\":\"Protocol translator API internal error.\",\"data\":\"Could not send "
                     "crypto API event.\"}",
                     response_str);
        json_decref(result);
        free(response_str);

        check_connection_free_expectations(test_ctx->connection, 26241, 0, 0 /* endpoints */);
        free_test_context(test_ctx, 1 /* registered_translators*/, 0 /* not_accepted_translators */, 0 /* endpoints */);
        mock().checkExpectations();

        deallocate_json_message_t(userdata);
        json_decref(request);
    }
}

TEST(protocol_api, test_asymmetric_verify_success)
{
    const char *public_key_name = "dlms";

    struct test_context *test_ctx = connection_initialized();
    test_registers_successfully(test_ctx);

    // Init rpc params object, one with missing and one with empty key field
    json_t *params = json_object();
    json_object_set_new(params, "public_key_name", json_string(public_key_name));
    json_object_set_new(params, "hash_digest", json_string(hash_base64));
    json_object_set_new(params, "signature", json_string(signature_base64));

    // Build rpc request object
    json_t *request = json_object();
    json_object_set_new(request, "jsonrpc", json_string("2.0"));
    json_object_set_new(request, "id", json_string("1"));
    json_object_set_new(request, "method", json_string("crypto_asymmetric_verify"));
    json_object_set_new(request, "params", params);

    char *data = json_dumps(request, JSON_COMPACT);
    struct json_message_t *userdata = alloc_json_message_t(data, strlen(data), test_ctx->connection);
    free(data);
    json_t *result = NULL;
    mock().expectOneCall("edgeclient_is_shutting_down").andReturnValue(false);
    mock().expectOneCall("eventOS_event_send")
            .withIntParameter("event_id", CRYPTO_API_EVENT_ASYMMETRIC_VERIFY)
            .withIntParameter("receiver", crypto_api_tasklet_id)
            .andReturnValue(0);
    int status = crypto_api_asymmetric_verify(request, params, &result, userdata);
    CHECK_EQUAL(-1, status);

    mock().expectOneCall("kcm_asymmetric_verify")
        .withMemoryBufferParameter("public_key_name", (const unsigned char*) public_key_name, strlen(public_key_name))
        .withMemoryBufferParameter("hash_digest", hash, hash_len)
        .withMemoryBufferParameter("signature", signaturebytes, signaturebytes_len)
        .andReturnValue(KCM_STATUS_SUCCESS);
    mock().expectOneCall("lws_callback_on_writable").andReturnValue(1);
    char *expected_data = NULL;
    asprintf(&expected_data,
             "{\"id\":\"1\",\"jsonrpc\":\"2.0\",\"result\":\"ok\"}");
    MyJsonFrame frame = MyJsonFrame(expected_data);
    MyJsonFrameComparator comparator;
    mock().installComparator("MyJsonFrame", comparator);

    expect_event_message_without_get_base(g_program_context->ev_base, safe_response_callback, true /* succeeds */);
    CHECK_EQUAL(true, eventOS_mock_event_handle());
    mock().expectOneCall("lws_write").withParameterOfType("MyJsonFrame", "buf", (const void *) &frame);
    evbase_mock_call_assigned_event_cb(g_program_context->ev_base, true);

    check_connection_free_expectations(test_ctx->connection, 26241, 0, 0 /* endpoints */);
    free_test_context(test_ctx, 1 /* registered_translators*/, 0 /* not_accepted_translators */, 0 /* endpoints */);
    mock().checkExpectations();

    deallocate_json_message_t(userdata);
    json_decref(request);
    free(expected_data);
}

TEST(protocol_api, test_asymmetric_verify_failure)
{
    const char *public_key_name = "dlms";

    struct test_context *test_ctx = connection_initialized();
    test_registers_successfully(test_ctx);

    // Init rpc params object, one with missing and one with empty key field
    json_t *params = json_object();
    json_object_set_new(params, "public_key_name", json_string(public_key_name));
    json_object_set_new(params, "hash_digest", json_string(hash_base64));
    json_object_set_new(params, "signature", json_string(signature_base64));

    // Build rpc request object
    json_t *request = json_object();
    json_object_set_new(request, "jsonrpc", json_string("2.0"));
    json_object_set_new(request, "id", json_string("1"));
    json_object_set_new(request, "method", json_string("crypto_asymmetric_verify"));
    json_object_set_new(request, "params", params);

    char *data = json_dumps(request, JSON_COMPACT);
    struct json_message_t *userdata = alloc_json_message_t(data, strlen(data), test_ctx->connection);
    free(data);
    json_t *result = NULL;
    mock().expectOneCall("edgeclient_is_shutting_down").andReturnValue(false);
    mock().expectOneCall("eventOS_event_send")
            .withIntParameter("event_id", CRYPTO_API_EVENT_ASYMMETRIC_VERIFY)
            .withIntParameter("receiver", crypto_api_tasklet_id)
            .andReturnValue(0);
    int status = crypto_api_asymmetric_verify(request, params, &result, userdata);
    CHECK_EQUAL(-1, status);

    mock().expectOneCall("kcm_asymmetric_verify")
        .withMemoryBufferParameter("public_key_name", (const unsigned char*) public_key_name, strlen(public_key_name))
        .withMemoryBufferParameter("hash_digest", hash, hash_len)
        .withMemoryBufferParameter("signature", signaturebytes, signaturebytes_len)
        .andReturnValue(KCM_STATUS_ITEM_NOT_FOUND);
    mock().expectOneCall("lws_callback_on_writable").andReturnValue(1);
    char *expected_data = NULL;
    asprintf(&expected_data,
             "{\"id\":\"1\",\"jsonrpc\":\"2.0\","
             "\"error\":{\"code\":-30000,\"data\":\"Got error when verifying, error "
             "%d (KCM_STATUS_ITEM_NOT_FOUND)\",\"message\":\"Protocol translator API internal "
             "error.\"}}", KCM_STATUS_ITEM_NOT_FOUND);
    MyJsonFrame frame = MyJsonFrame(expected_data);
    MyJsonFrameComparator comparator;
    mock().installComparator("MyJsonFrame", comparator);

    expect_event_message_without_get_base(g_program_context->ev_base, safe_response_callback, true /* succeeds */);
    CHECK_EQUAL(true, eventOS_mock_event_handle());
    mock().expectOneCall("lws_write").withParameterOfType("MyJsonFrame", "buf", (const void *) &frame);
    evbase_mock_call_assigned_event_cb(g_program_context->ev_base, true);

    check_connection_free_expectations(test_ctx->connection, 26241, 0, 0 /* endpoints */);
    free_test_context(test_ctx, 1 /* registered_translators*/, 0 /* not_accepted_translators */, 0 /* endpoints */);
    mock().checkExpectations();

    deallocate_json_message_t(userdata);
    json_decref(request);
    free(expected_data);
}

TEST(protocol_api, test_asymmetric_verify_invalid_length_signature)
{
    const char *public_key_name = "dlms";
    const char *long_base64 = "bG9uZ3Rlc3RzaWduYXR1cmV0b2dldGxvbmdlcnRoYW42NGJ5dGVzcmF3c2lnbmF0dXJldG90ZXN0ZXJyb3JjYXNlCg==";
    struct test_context *test_ctx = connection_initialized();
    test_registers_successfully(test_ctx);

    // Init rpc params object
    json_t *params = json_object();
    json_object_set_new(params, "public_key_name", json_string(public_key_name));
    json_object_set_new(params, "hash_digest", json_string(hash_base64));
    json_object_set_new(params, "signature", json_string(long_base64));

    // Build rpc request object
    json_t *request = json_object();
    json_object_set_new(request, "jsonrpc", json_string("2.0"));
    json_object_set_new(request, "id", json_string("1"));
    json_object_set_new(request, "method", json_string("crypto_asymmetric_verify"));
    json_object_set_new(request, "params", params);

    char *data = json_dumps(request, JSON_COMPACT);
    struct json_message_t *userdata = alloc_json_message_t(data, strlen(data), test_ctx->connection);
    free(data);
    json_t *result = NULL;
    mock().expectOneCall("edgeclient_is_shutting_down").andReturnValue(false);
    mock().expectOneCall("eventOS_event_send")
            .withIntParameter("event_id", CRYPTO_API_EVENT_ASYMMETRIC_VERIFY)
            .withIntParameter("receiver", crypto_api_tasklet_id)
            .andReturnValue(0);
    int status = crypto_api_asymmetric_verify(request, params, &result, userdata);
    CHECK_EQUAL(-1, status);

    mock().expectOneCall("lws_callback_on_writable").andReturnValue(1);
    char *expected_data = NULL;
    asprintf(&expected_data,
             "{\"id\":\"1\",\"jsonrpc\":\"2.0\","
             "\"error\":{\"code\":-30000,\"data\":\"Invalid signature or hash length.\","
             "\"message\":\"Protocol translator API internal error.\"}}");
    MyJsonFrame frame = MyJsonFrame(expected_data);
    MyJsonFrameComparator comparator;
    mock().installComparator("MyJsonFrame", comparator);

    expect_event_message_without_get_base(g_program_context->ev_base, safe_response_callback, true /* succeeds */);
    CHECK_EQUAL(true, eventOS_mock_event_handle());
    mock().expectOneCall("lws_write").withParameterOfType("MyJsonFrame", "buf", (const void *) &frame);
    evbase_mock_call_assigned_event_cb(g_program_context->ev_base, true);

    check_connection_free_expectations(test_ctx->connection, 26241, 0, 0 /* endpoints */);
    free_test_context(test_ctx, 1 /* registered_translators*/, 0 /* not_accepted_translators */, 0 /* endpoints */);
    mock().checkExpectations();

    deallocate_json_message_t(userdata);
    json_decref(request);
    free(expected_data);
}

TEST(protocol_api, test_asymmetric_verify_invalid_length_hash)
{
    const char *public_key_name = "dlms";
    const char *long_base64 = "bG9uZ3Rlc3RzaWduYXR1cmV0b2dldGxvbmdlcnRoYW42NGJ5dGVzcmF3c2lnbmF0dXJldG90ZXN0ZXJyb3JjYXNlCg==";
    struct test_context *test_ctx = connection_initialized();
    test_registers_successfully(test_ctx);

    // Init rpc params object
    json_t *params = json_object();
    json_object_set_new(params, "public_key_name", json_string(public_key_name));
    json_object_set_new(params, "hash_digest", json_string(long_base64));
    json_object_set_new(params, "signature", json_string(signature_base64));

    // Build rpc request object
    json_t *request = json_object();
    json_object_set_new(request, "jsonrpc", json_string("2.0"));
    json_object_set_new(request, "id", json_string("1"));
    json_object_set_new(request, "method", json_string("crypto_asymmetric_verify"));
    json_object_set_new(request, "params", params);

    char *data = json_dumps(request, JSON_COMPACT);
    struct json_message_t *userdata = alloc_json_message_t(data, strlen(data), test_ctx->connection);
    free(data);
    json_t *result = NULL;
    mock().expectOneCall("edgeclient_is_shutting_down").andReturnValue(false);
    mock().expectOneCall("eventOS_event_send")
            .withIntParameter("event_id", CRYPTO_API_EVENT_ASYMMETRIC_VERIFY)
            .withIntParameter("receiver", crypto_api_tasklet_id)
            .andReturnValue(0);
    int status = crypto_api_asymmetric_verify(request, params, &result, userdata);
    CHECK_EQUAL(-1, status);

    mock().expectOneCall("lws_callback_on_writable").andReturnValue(1);
    char *expected_data = NULL;
    asprintf(&expected_data,
             "{\"id\":\"1\",\"jsonrpc\":\"2.0\","
             "\"error\":{\"code\":-30000,\"data\":\"Invalid signature or hash length.\","
             "\"message\":\"Protocol translator API internal error.\"}}");
    MyJsonFrame frame = MyJsonFrame(expected_data);
    MyJsonFrameComparator comparator;
    mock().installComparator("MyJsonFrame", comparator);

    expect_event_message_without_get_base(g_program_context->ev_base, safe_response_callback, true /* succeeds */);
    CHECK_EQUAL(true, eventOS_mock_event_handle());
    mock().expectOneCall("lws_write").withParameterOfType("MyJsonFrame", "buf", (const void *) &frame);
    evbase_mock_call_assigned_event_cb(g_program_context->ev_base, true);

    check_connection_free_expectations(test_ctx->connection, 26241, 0, 0 /* endpoints */);
    free_test_context(test_ctx, 1 /* registered_translators*/, 0 /* not_accepted_translators */, 0 /* endpoints */);
    mock().checkExpectations();

    deallocate_json_message_t(userdata);
    json_decref(request);
    free(expected_data);
}

unsigned char peer_public_key[] = {
    0x08, 0x7d, 0xb3, 0x9f, 0x16, 0x61, 0xb5, 0xaa, 0xb5, 0x89, 0xb3, 0x4d,
    0xc3, 0x47, 0x60, 0x9c, 0xda, 0x66, 0x8e, 0xed, 0x30, 0x92, 0xa7, 0x15,
    0x17, 0xf0, 0x7c, 0x40, 0x8e, 0x2b, 0x20, 0xb5, 0xf6, 0x47, 0x0f, 0x4f,
    0x73, 0x3e, 0xa1, 0xe4, 0x92, 0x4e, 0x19, 0x61, 0x43, 0xcd, 0x65, 0x97,
    0xd7, 0x84, 0x49, 0x52, 0x81, 0xfe, 0xfe, 0x49, 0x8a, 0x55, 0x14, 0x11,
    0xcb, 0x95, 0x31, 0x88, 0x3d
};
unsigned int peer_public_key_len = 65;
const char *peer_public_key_base64 = "CH2znxZhtaq1ibNNw0dgnNpmju0wkqcVF/B8QI4rILX2Rw9Pcz6h5JJOGWFDzWWX14RJUoH+/kmKVRQRy5UxiD0=";

unsigned char shared_secret[] = {
    0x71, 0x66, 0xa6, 0xf2, 0x44, 0x28, 0x3b, 0x24, 0xd4, 0x61, 0x17, 0x53,
    0xa2, 0xa3, 0xa1, 0x77, 0x1f, 0x64, 0x69, 0xa9, 0x0a, 0xd1, 0x0b, 0x65,
    0xea, 0x7a, 0xad, 0x23, 0xdf, 0xad, 0x3c, 0x7e
};
size_t shared_secret_len = 32;
const char *shared_secret_base64 = "cWam8kQoOyTUYRdToqOhdx9kaakK0Qtl6nqtI9+tPH4=";

TEST(protocol_api, test_ecdh_key_agreement_success)
{
    const char *private_key_name = "dlms";

    struct test_context *test_ctx = connection_initialized();
    test_registers_successfully(test_ctx);

    // Init rpc params object, one with missing and one with empty key field
    json_t *params = json_object();
    json_object_set_new(params, "private_key_name", json_string(private_key_name));
    json_object_set_new(params, "peer_public_key", json_string(peer_public_key_base64));

    // Build rpc request object
    json_t *request = json_object();
    json_object_set_new(request, "jsonrpc", json_string("2.0"));
    json_object_set_new(request, "id", json_string("1"));
    json_object_set_new(request, "method", json_string("crypto_ecdh_key_agreement"));
    json_object_set_new(request, "params", params);

    char *data = json_dumps(request, JSON_COMPACT);
    struct json_message_t *userdata = alloc_json_message_t(data, strlen(data), test_ctx->connection);
    free(data);
    json_t *result = NULL;
    mock().expectOneCall("edgeclient_is_shutting_down").andReturnValue(false);
    mock().expectOneCall("eventOS_event_send")
            .withIntParameter("event_id", CRYPTO_API_EVENT_ECDH_KEY_AGREEMENT)
            .withIntParameter("receiver", crypto_api_tasklet_id)
            .andReturnValue(0);
    int status = crypto_api_ecdh_key_agreement(request, params, &result, userdata);
    CHECK_EQUAL(-1, status);

    mock().expectOneCall("kcm_ecdh_key_agreement")
        .withMemoryBufferParameter("private_key_name", (const unsigned char*) private_key_name, strlen(private_key_name))
        .withMemoryBufferParameter("peer_public_key", peer_public_key, peer_public_key_len)
        .withOutputParameterReturning("shared_secret", shared_secret, shared_secret_len)
        .withUnsignedIntParameter("shared_secret_max_size", KCM_EC_SECP256R1_SHARED_SECRET_SIZE)
        .withOutputParameterReturning("shared_secret_act_size_out", &shared_secret_len, sizeof(shared_secret_len))
        .andReturnValue(KCM_STATUS_SUCCESS);
    mock().expectOneCall("lws_callback_on_writable").andReturnValue(1);
    char *expected_data = NULL;
    asprintf(&expected_data,
             "{\"id\":\"1\",\"jsonrpc\":\"2.0\",\"result\":{\"shared_secret\":\"%s\"}}",
             shared_secret_base64);
    MyJsonFrame frame = MyJsonFrame(expected_data);
    MyJsonFrameComparator comparator;
    mock().installComparator("MyJsonFrame", comparator);

    expect_event_message_without_get_base(g_program_context->ev_base, safe_response_callback, true /* succeeds */);
    CHECK_EQUAL(true, eventOS_mock_event_handle());
    mock().expectOneCall("lws_write").withParameterOfType("MyJsonFrame", "buf", (const void *) &frame);
    evbase_mock_call_assigned_event_cb(g_program_context->ev_base, true);

    check_connection_free_expectations(test_ctx->connection, 26241, 0, 0 /* endpoints */);
    free_test_context(test_ctx, 1 /* registered_translators*/, 0 /* not_accepted_translators */, 0 /* endpoints */);
    mock().checkExpectations();

    deallocate_json_message_t(userdata);
    json_decref(request);
    free(expected_data);
}

TEST(protocol_api, test_ecdh_key_agreement_failure)
{
    const char *private_key_name = "dlms";

    struct test_context *test_ctx = connection_initialized();
    test_registers_successfully(test_ctx);

    // Init rpc params object, one with missing and one with empty key field
    json_t *params = json_object();
    json_object_set_new(params, "private_key_name", json_string(private_key_name));
    json_object_set_new(params, "peer_public_key", json_string(peer_public_key_base64));

    // Build rpc request object
    json_t *request = json_object();
    json_object_set_new(request, "jsonrpc", json_string("2.0"));
    json_object_set_new(request, "id", json_string("1"));
    json_object_set_new(request, "method", json_string("crypto_ecdh_key_agreement"));
    json_object_set_new(request, "params", params);

    char *data = json_dumps(request, JSON_COMPACT);
    struct json_message_t *userdata = alloc_json_message_t(data, strlen(data), test_ctx->connection);
    free(data);
    json_t *result = NULL;
    mock().expectOneCall("edgeclient_is_shutting_down").andReturnValue(false);
    mock().expectOneCall("eventOS_event_send")
            .withIntParameter("event_id", CRYPTO_API_EVENT_ECDH_KEY_AGREEMENT)
            .withIntParameter("receiver", crypto_api_tasklet_id)
            .andReturnValue(0);
    int status = crypto_api_ecdh_key_agreement(request, params, &result, userdata);
    CHECK_EQUAL(-1, status);

    mock().expectOneCall("kcm_ecdh_key_agreement")
        .withMemoryBufferParameter("private_key_name", (const unsigned char*) private_key_name, strlen(private_key_name))
        .withMemoryBufferParameter("peer_public_key", peer_public_key, peer_public_key_len)
        .withOutputParameterReturning("shared_secret", shared_secret, shared_secret_len)
        .withUnsignedIntParameter("shared_secret_max_size", KCM_EC_SECP256R1_SHARED_SECRET_SIZE)
        .withOutputParameterReturning("shared_secret_act_size_out", &shared_secret_len, sizeof(shared_secret_len))
        .andReturnValue(KCM_STATUS_INVALID_PARAMETER);
    mock().expectOneCall("lws_callback_on_writable").andReturnValue(1);
    char *expected_data = NULL;
    asprintf(&expected_data,
             "{\"id\":\"1\",\"jsonrpc\":\"2.0\","
             "\"error\":{\"code\":-30000,\"data\":\"Got error during ECDH key agreement, error "
             "%d (KCM_STATUS_INVALID_PARAMETER)\",\"message\":\"Protocol translator API internal "
             "error.\"}}", KCM_STATUS_INVALID_PARAMETER);
    MyJsonFrame frame = MyJsonFrame(expected_data);
    MyJsonFrameComparator comparator;
    mock().installComparator("MyJsonFrame", comparator);

    expect_event_message_without_get_base(g_program_context->ev_base, safe_response_callback, true /* succeeds */);
    CHECK_EQUAL(true, eventOS_mock_event_handle());
    mock().expectOneCall("lws_write").withParameterOfType("MyJsonFrame", "buf", (const void *) &frame);
    evbase_mock_call_assigned_event_cb(g_program_context->ev_base, true);

    check_connection_free_expectations(test_ctx->connection, 26241, 0, 0 /* endpoints */);
    free_test_context(test_ctx, 1 /* registered_translators*/, 0 /* not_accepted_translators */, 0 /* endpoints */);
    mock().checkExpectations();

    deallocate_json_message_t(userdata);
    json_decref(request);
    free(expected_data);
}

TEST(protocol_api, test_apis_no_service)
{
    for (int i = 0; method_table[i].name != NULL; i++) {
        struct test_context *test_ctx = protocol_translator_registered(0);
        // Init rpc params object
        json_t *params = json_object();

        // Build rpc request object
        json_t *request = json_object();
        json_object_set_new(request, "jsonrpc", json_string("2.0"));
        json_object_set_new(request, "id", json_string("1"));
        json_object_set_new(request, "method", json_string(method_table[i].name));
        json_object_set_new(request, "params", params);

        char *data = json_dumps(request, JSON_COMPACT);
        struct json_message_t *userdata = alloc_json_message_t(data, strlen(data), test_ctx->connection);
        free(data);
        json_t *result = NULL;
        mock().expectOneCall("edgeclient_is_shutting_down").andReturnValue(true);
        int status = method_table[i].funcptr(request, params, &result, userdata);
        CHECK_EQUAL(1, status);
        char *response_str = json_dumps(result, JSON_COMPACT);
        STRCMP_EQUAL("{\"code\":-30006,\"message\":\"Edge Core is shutting down.\",\"data\":\"Service unavailable, because "
                     "the server is shutting down\"}",
                     response_str);

        check_connection_free_expectations(test_ctx->connection, 26241, 0, 0 /* endpoints */);
        deallocate_json_message_t(userdata);

        free_test_context(test_ctx, 0 /* registered_translators*/, 0 /* not_accepted_translators */, 0 /* endpoints */);
        mock().checkExpectations();
        free(response_str);
        json_decref(request);
        json_decref(result);
    }
}


TEST(protocol_api, test_apis_no_request_id)
{
    for (int i = 0; method_table[i].name != NULL; i++) {
        struct test_context *test_ctx = protocol_translator_registered(0);
        // Init rpc params object, one with missing and one with empty key field
        json_t *params = json_object();

        // Build rpc request object
        json_t *request = json_object();
        json_object_set_new(request, "jsonrpc", json_string("2.0"));
        json_object_set_new(request, "method", json_string(method_table[i].name));
        json_object_set_new(request, "params", params);

        char *data = json_dumps(request, JSON_COMPACT);
        struct json_message_t *userdata = alloc_json_message_t(data, strlen(data), test_ctx->connection);
        free(data);
        json_t *result = NULL;
        mock().expectOneCall("edgeclient_is_shutting_down").andReturnValue(false);
        int status = method_table[i].funcptr(request, params, &result, userdata);
        CHECK_EQUAL(1, status);
        json_t *code_handle = json_object_get(result, "code");
        CHECK_EQUAL(JSONRPC_INVALID_PARAMS, json_integer_value(code_handle));
        json_t *msg_handle = json_object_get(result, "message");
        STRCMP_EQUAL("Invalid params", json_string_value(msg_handle));

        check_connection_free_expectations(test_ctx->connection, 26241, 0, 0 /* endpoints */);
        deallocate_json_message_t(userdata);

        free_test_context(test_ctx, 0 /* registered_translators*/, 0 /* not_accepted_translators */, 0 /* endpoints */);
        mock().checkExpectations();
        json_decref(request);
        json_decref(result);
    }
}

const unsigned char test_csr[] = {
    0x30, 0x82, 0x01, 0x11, 0x30, 0x81, 0xb8, 0x02, 0x01, 0x00, 0x30, 0x56,
    0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x46,
    0x49, 0x31, 0x0d, 0x30, 0x0b, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x04,
    0x4f, 0x75, 0x6c, 0x75, 0x31, 0x0d, 0x30, 0x0b, 0x06, 0x03, 0x55, 0x04,
    0x07, 0x0c, 0x04, 0x4f, 0x75, 0x6c, 0x75, 0x31, 0x0c, 0x30, 0x0a, 0x06,
    0x03, 0x55, 0x04, 0x0a, 0x0c, 0x03, 0x41, 0x52, 0x4d, 0x31, 0x0c, 0x30,
    0x0a, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x0c, 0x03, 0x49, 0x53, 0x47, 0x31,
    0x0d, 0x30, 0x0b, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x04, 0x44, 0x4c,
    0x4d, 0x53, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce,
    0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01,
    0x07, 0x03, 0x42, 0x00, 0x04, 0x20, 0x2c, 0xfe, 0x4b, 0x81, 0x37, 0x2c,
    0x86, 0x45, 0xfc, 0xdd, 0x2c, 0x44, 0xc6, 0x71, 0xc7, 0x9f, 0x5b, 0xd6,
    0xc7, 0x65, 0xca, 0x50, 0x19, 0xf0, 0x86, 0x2a, 0x11, 0x5a, 0xaa, 0x13,
    0x2d, 0xd4, 0x26, 0x45, 0x59, 0x1d, 0xc9, 0x4c, 0x18, 0x0b, 0x85, 0xb4,
    0x8d, 0xa0, 0x7d, 0xe8, 0x0f, 0xb9, 0x28, 0x60, 0xb5, 0x48, 0x55, 0xce,
    0x2f, 0xe9, 0xd9, 0xc0, 0xf1, 0xcc, 0xbc, 0x4d, 0xa8, 0xa0, 0x00, 0x30,
    0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03,
    0x48, 0x00, 0x30, 0x45, 0x02, 0x20, 0x13, 0x41, 0x09, 0xc5, 0x11, 0xaa,
    0xe5, 0x84, 0x40, 0xbf, 0x0e, 0xcc, 0x78, 0x8a, 0x4d, 0x01, 0xdf, 0x84,
    0xfd, 0x34, 0x9a, 0xca, 0x94, 0xa1, 0xc6, 0xd2, 0x36, 0x20, 0x81, 0xf9,
    0x50, 0x43, 0x02, 0x21, 0x00, 0xcd, 0x66, 0xf6, 0xf3, 0x64, 0x99, 0xcb,
    0x44, 0xea, 0x7a, 0x0b, 0x33, 0x3f, 0x03, 0x2e, 0xd1, 0x06, 0xb7, 0xd5,
    0x82, 0x0b, 0xad, 0xcd, 0xd8, 0x54, 0x2b, 0xbd, 0x1c, 0x77, 0x38, 0x9a,
    0x83
};
const unsigned int test_csr_len = 277;
const char* test_csr_base64 = "MIIBETCBuAIBADBWMQswCQYDVQQGEwJGSTENMAsGA1UECAwET3VsdTENMAsGA1UEBwwET3VsdTEMMAoGA1UECgwDQVJNMQwwCgYDVQQLDANJU0cxDTALBgNVBAMMBERMTVMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQgLP5LgTcshkX83SxExnHHn1vWx2XKUBnwhioRWqoTLdQmRVkdyUwYC4W0jaB96A+5KGC1SFXOL+nZwPHMvE2ooAAwCgYIKoZIzj0EAwIDSAAwRQIgE0EJxRGq5YRAvw7MeIpNAd+E/TSaypShxtI2IIH5UEMCIQDNZvbzZJnLROp6CzM/Ay7RBrfVggutzdhUK70cdziagw==";

TEST(protocol_api, test_est_enrollment_success)
{
    const char *public_key_name = "dlms";

    struct test_context *test_ctx = connection_initialized();
    test_registers_successfully(test_ctx);

    // Init rpc params object, one with missing and one with empty key field
    json_t *params = json_object();
    json_object_set_new(params, "certificate_name", json_string(public_key_name));
    json_object_set_new(params, "csr", json_string(test_csr_base64));

    // Build rpc request object
    json_t *request = json_object();
    json_object_set_new(request, "jsonrpc", json_string("2.0"));
    json_object_set_new(request, "id", json_string("1"));
    json_object_set_new(request, "method", json_string("est_request_enrollment"));
    json_object_set_new(request, "params", params);

    char *data = json_dumps(request, JSON_COMPACT);
    struct json_message_t *userdata = alloc_json_message_t(data, strlen(data), test_ctx->connection);
    free(data);
    json_t *result = NULL;
    mock().expectOneCall("edgeclient_is_shutting_down").andReturnValue(false);
    mock().expectOneCall("edgeclient_request_est_enrollment")
        .withStringParameter("certificate_name", (const char*) public_key_name)
        .withMemoryBufferParameter("csr", test_csr, test_csr_len)
        .ignoreOtherParameters()
        .andReturnValue(PT_API_SUCCESS);
    int status = est_request_enrollment(request, params, &result, userdata);
    CHECK_EQUAL(JSONRPC_RETURN_CODE_NO_RESPONSE, status);

    check_connection_free_expectations(test_ctx->connection, 26241, 0, 0 /* endpoints */);
    free_test_context(test_ctx, 1 /* registered_translators*/, 0 /* not_accepted_translators */, 0 /* endpoints */);
    mock().checkExpectations();

    void *context_param = mock().getData("est_context_parameter").getPointerValue();
    protocol_api_free_async_ctx_func((rpc_request_context_t *) context_param);

    deallocate_json_message_t(userdata);
    json_decref(request);
    json_decref(result);
}

TEST(protocol_api, test_est_enrollment_failure)
{
    const char *public_key_name = "dlms";

    struct test_context *test_ctx = connection_initialized();
    test_registers_successfully(test_ctx);

    // Init rpc params object, one with missing and one with empty key field
    json_t *params = json_object();
    json_object_set_new(params, "certificate_name", json_string(public_key_name));
    json_object_set_new(params, "csr", json_string(test_csr_base64));

    // Build rpc request object
    json_t *request = json_object();
    json_object_set_new(request, "jsonrpc", json_string("2.0"));
    json_object_set_new(request, "id", json_string("1"));
    json_object_set_new(request, "method", json_string("est_request_enrollment"));
    json_object_set_new(request, "params", params);

    char *data = json_dumps(request, JSON_COMPACT);
    struct json_message_t *userdata = alloc_json_message_t(data, strlen(data), test_ctx->connection);
    free(data);
    json_t *result = NULL;
    mock().expectOneCall("edgeclient_is_shutting_down").andReturnValue(false);
    mock().expectOneCall("edgeclient_request_est_enrollment")
        .withStringParameter("certificate_name", (const char*) public_key_name)
        .withMemoryBufferParameter("csr", test_csr, test_csr_len)
        .ignoreOtherParameters()
        .andReturnValue(PT_API_INTERNAL_ERROR);
    int status = est_request_enrollment(request, params, &result, userdata);
    CHECK_EQUAL(JSONRPC_RETURN_CODE_ERROR, status);

    check_connection_free_expectations(test_ctx->connection, 26241, 0, 0 /* endpoints */);
    free_test_context(test_ctx, 1 /* registered_translators*/, 0 /* not_accepted_translators */, 0 /* endpoints */);
    mock().checkExpectations();

    deallocate_json_message_t(userdata);
    json_decref(request);
    json_decref(result);
}

typedef struct {
    const char *cert_name;
    const char *csr;
} est_test_params_t;

const est_test_params_t invalid_est_params[] = {
    {
        .cert_name = "",
        .csr = test_csr_base64,
    },
    {
        .cert_name = "dlms",
        .csr = "",
    },
    {
        .cert_name = "",
        .csr = "",
    },
    {
        .cert_name = NULL,
        .csr = test_csr_base64,
    },
    {
        .cert_name = "dlms",
        .csr = NULL,
    },
    {
        .cert_name = NULL,
        .csr = NULL,
    }
};

TEST(protocol_api, test_est_enrollment_invalid_parameters)
{
    for (unsigned int i = 0; i < sizeof(invalid_est_params) / sizeof(est_test_params_t); i++) {
        struct test_context *test_ctx = connection_initialized();
        test_registers_successfully(test_ctx);

        // Init rpc params object, one with missing and one with empty key field
        json_t *params = json_object();
        if (invalid_est_params[i].cert_name != NULL) {
            json_object_set_new(params, "certificate_name", json_string(invalid_est_params[i].cert_name));
        }
        if (invalid_est_params[i].csr != NULL) {
            json_object_set_new(params, "csr", json_string(invalid_est_params[i].csr));
        }

        // Build rpc request object
        json_t *request = json_object();
        json_object_set_new(request, "jsonrpc", json_string("2.0"));
        json_object_set_new(request, "id", json_string("1"));
        json_object_set_new(request, "method", json_string("est_request_enrollment"));
        json_object_set_new(request, "params", params);

        char *data = json_dumps(request, JSON_COMPACT);
        struct json_message_t *userdata = alloc_json_message_t(data, strlen(data), test_ctx->connection);
        free(data);
        json_t *result = NULL;
        mock().expectOneCall("edgeclient_is_shutting_down").andReturnValue(false);
        int status = est_request_enrollment(request, params, &result, userdata);
        CHECK_EQUAL(JSONRPC_RETURN_CODE_ERROR, status);

        check_connection_free_expectations(test_ctx->connection, 26241, 0, 0 /* endpoints */);
        free_test_context(test_ctx, 1 /* registered_translators*/, 0 /* not_accepted_translators */, 0 /* endpoints */);
        mock().checkExpectations();

        deallocate_json_message_t(userdata);
        json_decref(request);
        json_decref(result);
    }
}

void est_enrollment_notifier_tester(struct cert_chain_context_s *chain_ctx, const char *expected_data)
{
    struct test_context *test_ctx = connection_initialized();
    test_registers_successfully(test_ctx);

    protocol_api_async_request_context_t *ctx = (protocol_api_async_request_context_t *) calloc(1, sizeof(protocol_api_async_request_context_t));
    json_t *request_id = json_string("requestid");
    ctx->request_id = json_dumps(request_id, JSON_COMPACT|JSON_ENCODE_ANY);
    json_decref(request_id);
    ctx->connection_id = test_ctx->connection->id;

    MyJsonFrame frame = MyJsonFrame(expected_data);
    MyJsonFrameComparator comparator;
    mock().installComparator("MyJsonFrame", comparator);

    expect_event_message_without_get_base(g_program_context->ev_base, safe_response_callback, true /* succeeds */);

    int rc = est_enrollment_result_notifier(EST_ENROLLMENT_SUCCESS, chain_ctx, ctx);
    CHECK_EQUAL(0, rc);

    mock().expectOneCall("lws_callback_on_writable").andReturnValue(1);
    mock().expectOneCall("lws_write").withParameterOfType("MyJsonFrame", "buf", (const void *) &frame);
    evbase_mock_call_assigned_event_cb(g_program_context->ev_base, true);

    check_connection_free_expectations(test_ctx->connection, 26241, 0, 0 /* endpoints */);
    free_test_context(test_ctx, 1 /* registered_translators*/, 0 /* not_accepted_translators */, 0 /* endpoints */);

    mock().checkExpectations();
}

const char *cert2_base64 = "c2Vjb25kdGVzdGNlcnRpZmljYXRlCg==";

TEST(protocol_api, test_est_enrollment_notifier)
{
    char *expected_data = NULL;
    asprintf(&expected_data,
             "{\"error\":{\"code\":-30000,\"data\":\"EST enrollment failed.\",\"message\":\"Protocol translator API internal error.\"},\"id\":\"requestid\",\"jsonrpc\":\"2.0\"}");

    est_enrollment_notifier_tester(NULL, expected_data);

    struct cert_chain_context_s chain_ctx = {0};
    est_enrollment_notifier_tester(&chain_ctx, expected_data);

    chain_ctx.chain_length = 1;
    est_enrollment_notifier_tester(&chain_ctx, expected_data);
    free(expected_data);

    struct cert_context_s cert1 = {0};
    size_t binary_len = apr_base64_decode_len(cert_data_base64);
    unsigned char *cert_data_binary = (unsigned char *) calloc(1, binary_len);
    apr_base64_decode_binary(cert_data_binary, cert_data_base64);
    cert1.cert = cert_data_binary;
    cert1.cert_length = binary_len;
    chain_ctx.certs = &cert1;

    asprintf(&expected_data,
             "{\"id\":\"requestid\",\"jsonrpc\":\"2.0\",\"result\":{\"certificate_data\":[\"%s\"]}}", cert_data_base64);
    est_enrollment_notifier_tester(&chain_ctx, expected_data);
    free(expected_data);

    struct cert_context_s cert2 = {0};
    size_t binary2_len = apr_base64_decode_len(cert2_base64);
    unsigned char *cert2_data_binary = (unsigned char *) calloc(1, binary2_len);
    apr_base64_decode_binary(cert2_data_binary, cert2_base64);
    cert2.cert = cert2_data_binary;
    cert2.cert_length = binary2_len;
    cert1.next = &cert2;
    chain_ctx.chain_length = 2;

    asprintf(&expected_data,
             "{\"id\":\"requestid\",\"jsonrpc\":\"2.0\",\"result\":{\"certificate_data\":[\"%s\",\"%s\"]}}", cert_data_base64, cert2_base64);
    est_enrollment_notifier_tester(&chain_ctx, expected_data);
    free(expected_data);

    free(cert_data_binary);
    free(cert2_data_binary);
}
