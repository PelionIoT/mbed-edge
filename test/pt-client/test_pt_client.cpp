#include "CppUTest/TestHarness.h"
#include "CppUTestExt/MockSupport.h"
#include "cpputest-custom-types/value_pointer.h"

extern "C" {
#include "jansson.h"
#include <string.h>
#include <event2/event.h>
#include <event2/bufferevent.h>
#include "pt-client/pt_api.h"
#include "pt-client/pt_api_internal.h"
#include "test-lib/evbase_mock.h"
#include "pt-client/client.h"
#include "common/edge_mutex.h"
#include "common/default_message_id_generator.h"
#include "common/websocket_comm.h"
#include "libwebsockets.h"
#include "libwebsocket-mock/lws_mock.h"
#include "cpputest-custom-types/my_json_frame.h"
#include "test-lib/json_helper.h"
#include "common/edge_trace.h"
}

#define EXPECTED_EDGE_PROTOCOL_API_VERSION "/1/pt"

int dummy_callback(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len)
{
    return 0;
}

struct interrupt_parameter;

typedef void (*test_func_t)(struct interrupt_parameter *);

struct interrupt_parameter {
    struct event_base *base;
    struct connection **connection;
    void *userdata;
    short events;
    const char *socket_path;
    test_func_t test_func;
    pthread_t *tester_thread;
    bool connection_fails;
    bool expect_evthread_use_pthreads_failure;
    bool expect_cb_failure;
};

static struct interrupt_parameter *create_interrupt_parameter(struct event_base *base)
{
    struct interrupt_parameter *parameter =
            (struct interrupt_parameter *) calloc(1, sizeof(struct interrupt_parameter));
    parameter->base = base;
    parameter->connection = (struct connection**) calloc(1, sizeof(struct connection*));
    return parameter;
}

TEST_GROUP(pt_client) {
    void setup()
    {
    }

    void teardown()
    {
    }
};

static void expect_mutex_init_deinit()
{
    mock().expectOneCall("edge_mutex_init")
        .withPointerParameter("mutex", (void *) &rpc_mutex)
        .withUnsignedIntParameter("type", PTHREAD_MUTEX_ERRORCHECK)
        .andReturnValue(0);

    mock().expectOneCall("edge_mutex_destroy").withPointerParameter("mutex", (void *) &rpc_mutex).andReturnValue(0);
}

static void expect_mutexing()
{
    mock().expectOneCall("edge_mutex_lock").withPointerParameter("mutex", (void *) &rpc_mutex).andReturnValue(0);
    mock().expectOneCall("edge_mutex_unlock").withPointerParameter("mutex", (void *) &rpc_mutex).andReturnValue(0);
}

void test_connection_ready_handler(struct connection *connection, void* userdata)
{
    mock()
        .actualCall("test_connection_ready_handler")
        .withPointerParameter("connection", connection)
        .withPointerParameter("userdata", userdata);
}

void disconnected_handler(struct connection *connection, void *userdata)
{
    mock().actualCall("disconnected_handler");
}

void shutdown_handler(struct connection **connection, void *userdata)
{
    mock().actualCall("shutdown_handler")
            .withPointerParameter("connection", (void *) connection)
            .withPointerParameter("userdata", (void *) userdata);
}

static int write_handler(struct connection *connection,
                         const char *device_id, const uint16_t object_id,
                         const uint16_t instance_id,
                         const uint16_t resource_id,
                         const unsigned int operation,
                         const uint8_t *value, const uint32_t value_size,
                         void *userdata)
{
    ValuePointer *value_pointer = new ValuePointer((uint8_t *) value, value_size);
    int ret_val = mock().actualCall("write_handler")
                          .withPointerParameter("connnection", connection)
                          .withStringParameter("device_id", device_id)
                          .withIntParameter("object_id", object_id)
                          .withIntParameter("instance_id", instance_id)
                          .withIntParameter("resource_id", resource_id)
                          .withIntParameter("operation", operation)
                          .withParameterOfType("ValuePointer", "value", (void *) value_pointer)
                          .withLongIntParameter("value_size", value_size)
                          .withPointerParameter("userdata", userdata)
                          .returnIntValue();
    delete value_pointer;
    return ret_val;
}

static void init_pt_cbs_to_null(protocol_translator_callbacks_t *pt_cbs)
{
    pt_cbs->connection_ready_cb = NULL;
    pt_cbs->received_write_cb = NULL;
    pt_cbs->connection_shutdown_cb = NULL;
}

static void init_pt_cbs(protocol_translator_callbacks_t *pt_cbs)
{
    pt_cbs->connection_ready_cb = test_connection_ready_handler;
    pt_cbs->received_write_cb = write_handler;
    pt_cbs->connection_shutdown_cb = shutdown_handler;
    pt_cbs->disconnected_cb = disconnected_handler;
}


static bool close_condition_check_no_retries(bool close_client) {
    return 1; // Always close
}

static void start_client(struct interrupt_parameter *parameter,
                         protocol_translator_callbacks_t *pt_cbs,
                         int dispatch_return_value)
{
    char *name = (char*) "example_client";

    pt_init_check_close_condition_function(close_condition_check_no_retries);

    int evthread_use_pthreads_return_value = parameter->expect_evthread_use_pthreads_failure ? -1 : 0;
    mock().expectOneCall("evthread_use_pthreads").andReturnValue(evthread_use_pthreads_return_value);

    if(evthread_use_pthreads_return_value != -1) {
        mock().expectOneCall("event_base_new")
            .andReturnValue(parameter->base);
    }

    if (!parameter->expect_evthread_use_pthreads_failure && !parameter->expect_cb_failure) {
        expect_mutexing();
        if (parameter->base) {
            mock().expectOneCall("lws_set_log_level");
            mock().expectOneCall("lws_create_context");
            if (parameter->connection_fails) {
                lws_mock_setup_connection_failure();
            }
            mock().expectOneCall("lws_client_connect_via_info")
                    .withStringParameter("path", EXPECTED_EDGE_PROTOCOL_API_VERSION);
            if (parameter->connection_fails) {
                mock().expectOneCall("disconnected_handler");
                mock().expectOneCall("event_base_loopbreak").withPointerParameter("base", (void *) parameter->base);
                mock().expectOneCall("shutdown_handler")
                        .withPointerParameter("connection", parameter->connection)
                        .withPointerParameter("userdata", parameter->userdata);
            } else {
                mock().expectOneCall("event_base_dispatch")
                    .withPointerParameter("base", parameter->base)
                    .andReturnValue(dispatch_return_value);

                if (dispatch_return_value != -1) {
                    mock().expectOneCall("event_base_loopbreak").withPointerParameter("base", (void *) parameter->base);
                    mock().expectOneCall("shutdown_handler")
                            .withPointerParameter("connection", parameter->connection)
                            .withPointerParameter("userdata", parameter->userdata);
                }
            }
            mock().expectOneCall("lws_context_destroy");
        }
    }
    mock().expectOneCall("event_base_free")
            .withPointerParameter("base", parameter->base);
    mock().expectOneCall("libevent_global_shutdown");
    pt_client_start(parameter->socket_path, name, pt_cbs, parameter->userdata, parameter->connection);
}

TEST(pt_client, test_initialize_and_destroy_trace_api)
{
    mock().expectOneCall("edge_mutex_init")
            .withPointerParameter("mutex", &trace_mutex)
            .withIntParameter("type", PTHREAD_MUTEX_RECURSIVE)
            .andReturnValue(0);
    edge_trace_init(1);
    mock().checkExpectations();

    mock().expectOneCall("edge_mutex_destroy").withPointerParameter("mutex", &trace_mutex).andReturnValue(0);
    edge_trace_destroy();
    mock().checkExpectations();
}

static void *client_shutdown_test_thread(void * param)
{
    struct interrupt_parameter *parameter = (struct interrupt_parameter *) param;
    struct event_base *base = parameter->base;
    evbase_mock_wait_until_event_loop(base);
    struct lws *wsi = lws_mock_get_wsi();
    websocket_connection_t *connection = (websocket_connection_t *) wsi->userdata;
    struct connection *conn = connection->conn;
    mock().expectOneCall("test_connection_ready_handler")
            .withPointerParameter("connection", conn)
            .withPointerParameter("userdata", conn->userdata);
    lws_mock_connection_established(lws_mock_get_wsi(), LWS_CALLBACK_CLIENT_ESTABLISHED);
    if (parameter->test_func) {
        parameter->test_func(parameter);
    }
    mock().expectOneCall("disconnected_handler");
    lws_mock_connection_closed(lws_mock_get_wsi());
    pt_client_shutdown(*(parameter->connection));
    return NULL;
}

static void clean_interrupt_thread_and_parameter(struct interrupt_parameter *parameter)
{
    if (parameter->base && parameter->base->event_loop_wait_simulation && parameter->tester_thread) {
        evbase_mock_release_interrupt_thread(parameter->base);
        pthread_join(*(parameter->tester_thread), NULL);
    }

    if (parameter->base) {
        if (parameter->base->event_loop_wait_simulation) {
            evbase_mock_release_interrupt_thread(parameter->base);
        }
        evbase_mock_delete(parameter->base);
    }

    free(parameter->tester_thread);
    free(*parameter->connection);
    free(parameter->connection);
    free(parameter);
}

static void test_start_and_shutdown_variant_common(const char *socket_path,
                                                   bool connection_fails,
                                                   test_func_t test_func)
{
    struct event_base *base = evbase_mock_new();
    struct interrupt_parameter *parameter = create_interrupt_parameter(base);
    parameter->connection_fails = connection_fails;
    parameter->socket_path = socket_path;
    parameter->test_func = test_func;
    expect_mutex_init_deinit();
    protocol_translator_callbacks_t pt_cbs;
    init_pt_cbs(&pt_cbs);
    if (!connection_fails) {
        evbase_mock_setup_event_loop_wait(base);
        parameter->tester_thread = (pthread_t *) calloc(1, sizeof(pthread_t));
        pthread_create(parameter->tester_thread, NULL, client_shutdown_test_thread, (void *) parameter);
    }
    start_client(parameter, &pt_cbs, 0);
    clean_interrupt_thread_and_parameter(parameter);
}

static void test_start_and_shutdown_variant(const char *socket_path, bool connection_fails)
{
    test_start_and_shutdown_variant_common(socket_path, connection_fails, NULL);
}

static void test_start_and_shutdown_variant_with_test_func(const char *socket_path, test_func_t test_func)
{
    test_start_and_shutdown_variant_common(socket_path, false, test_func);
}

static void test_callback_combination(pt_connection_ready_cb connection_ready_cb,
                                      pt_received_write_handler received_write_cb,
                                      pt_connection_shutdown_cb connection_shutdown_cb)
{
    struct interrupt_parameter *parameter = create_interrupt_parameter(NULL);
    parameter->expect_cb_failure = true;
    expect_mutex_init_deinit();
    expect_mutexing();
    protocol_translator_callbacks_t pt_cbs;
    pt_cbs.connection_ready_cb = connection_ready_cb;
    pt_cbs.received_write_cb = received_write_cb;
    pt_cbs.connection_shutdown_cb = connection_shutdown_cb;

    start_client(parameter, &pt_cbs, -1);
    clean_interrupt_thread_and_parameter(parameter);
}

TEST(pt_client, test_start_client_and_shutdown)
{
    test_start_and_shutdown_variant(NULL, false);
    mock().checkExpectations();
}

TEST(pt_client, test_start_client_and_shutdown_with_localhost)
{
    test_start_and_shutdown_variant("default-pt-socket", false);
    mock().checkExpectations();
}

static void test_lws_client_receive_invalid(struct interrupt_parameter *parameter)
{
    (void) parameter;
    unsigned char *data = (unsigned char *) "{ \"jsonrpc\": \"2.0\", \"method\": \"subtract\", \"id\" : \"1\" }";
    size_t len = 54;
    const char *expected_response =
            "{\"error\":{\"code\":-32601,\"message\":\"Method not found\"},\"id\":\"1\",\"jsonrpc\":\"2.0\"}";
    int32_t response_len = 79;
    MyJsonFrameComparator comparator;
    mock().installComparator("MyJsonFrame", comparator);
    mock().expectOneCall("lws_remaining_packet_payload").andReturnValue(0);
    mock().expectOneCall("lws_callback_on_writable").andReturnValue(0);
    MyJsonFrame *frame = new MyJsonFrame((const char *) expected_response, response_len);
    mock().expectOneCall("lws_write").withParameterOfType("MyJsonFrame", "buf", (const void *) frame).andReturnValue(0);
    lws_mock_callback_client_receive(data, len, 0);
    delete frame;
}

TEST(pt_client, test_lws_client_receive_callback_invalid_message)
{
    test_start_and_shutdown_variant_with_test_func("default-pt-socket", test_lws_client_receive_invalid);
    mock().checkExpectations();
}

static void test_lws_client_receive_protocol_error(struct interrupt_parameter *parameter)
{
    (void) parameter;
    // Note: following is not valid json.
    unsigned char *data = (unsigned char *) "[ \"jsonrpc\": \"2.0\", \"method\": \"subtract\", \"id\" : \"1\" }";
    size_t len = 54;
    mock().expectOneCall("lws_remaining_packet_payload").andReturnValue(0);
    mock().expectOneCall("lws_callback_on_writable").andReturnValue(-1);
    mock().expectOneCall("lws_close_reason");
    lws_mock_callback_client_receive(data, len, 0);
}

TEST(pt_client, test_lws_client_receive_callback_protocol_error)
{
    test_start_and_shutdown_variant_with_test_func("default-pt-socket", test_lws_client_receive_protocol_error);
    mock().checkExpectations();
}

static void test_lws_client_receive_valid(struct interrupt_parameter *parameter)
{
#define TEST_WRITE_FROM_EDGE_CORE TEST_DATA_DIR "/write_from_edge_core_test.json"
    // Load device registration jsonrpc parameters structure from file
    json_t *request = load_json_params(TEST_WRITE_FROM_EDGE_CORE);

    // Build device registration jsonrpc structure
    unsigned char *data = (unsigned char *) json_dumps(request, JSON_COMPACT);
    size_t len = strlen((char *) data);

    const char *expected_response = "{\"id\":\"1234567890\",\"jsonrpc\":\"2.0\",\"result\":\"ok\"}";
    int32_t response_len = 49;
    MyJsonFrameComparator comparator;
    mock().installComparator("MyJsonFrame", comparator);
    mock().expectOneCall("lws_remaining_packet_payload").andReturnValue(0);
    mock().expectOneCall("lws_callback_on_writable").andReturnValue(0);
    struct connection *connection = *parameter->connection;
    ValuePointer *value_pointer = new ValuePointer((const uint8_t *) "@(=p\243\327\n=", 8);
    mock().expectOneCall("write_handler")
            .withPointerParameter("connnection", connection)
            .withStringParameter("device_id", "device-id-1")
            .withIntParameter("object_id", 3306)
            .withIntParameter("instance_id", 0)
            .withIntParameter("resource_id", 5700)
            .withIntParameter("operation", 2)
            .withParameterOfType("ValuePointer", "value", value_pointer)
            .withLongIntParameter("value_size", 8)
            .withPointerParameter("userdata", 0)
            .andReturnValue(0);
    MyJsonFrame *response_frame = new MyJsonFrame((const char *) expected_response, response_len);
    mock().expectOneCall("lws_write")
            .withParameterOfType("MyJsonFrame", "buf", (const void *) response_frame)
            .andReturnValue(0);
    lws_mock_callback_client_receive(data, len, 0);
    free(data);
    json_decref(request);
    delete response_frame;
    delete value_pointer;
}

TEST(pt_client, test_lws_client_receive_callback_valid_message)
{
    test_start_and_shutdown_variant_with_test_func("default-pt-socket", test_lws_client_receive_valid);
    mock().checkExpectations();
}

TEST(pt_client, test_lws_connection_fails)
{
    test_start_and_shutdown_variant_common("default-pt-socket", true /* connection fails */, NULL);
    mock().checkExpectations();
}

TEST(pt_client, test_start_client_libevent_configuration_fails)
{
    struct interrupt_parameter *parameter = create_interrupt_parameter(NULL);

    parameter->expect_evthread_use_pthreads_failure = -1;
    expect_mutex_init_deinit();
    protocol_translator_callbacks_t pt_cbs;
    init_pt_cbs_to_null(&pt_cbs);

    expect_mutexing();
    start_client(parameter, &pt_cbs, -1);
    clean_interrupt_thread_and_parameter(parameter);
    mock().checkExpectations();
}

TEST(pt_client, test_start_client_incorrect_protocol_translator_callbacks)
{
    test_callback_combination(NULL, NULL, NULL);
    test_callback_combination(NULL, NULL, shutdown_handler);
    test_callback_combination(NULL, write_handler, NULL);
    test_callback_combination(NULL, write_handler, shutdown_handler);
    test_callback_combination(test_connection_ready_handler, NULL, NULL);
    test_callback_combination(test_connection_ready_handler, NULL, shutdown_handler);
    test_callback_combination(test_connection_ready_handler, write_handler, NULL);
    mock().checkExpectations();
}

TEST(pt_client, test_start_client_and_shutdown_base_allocation_fails)
{
    struct interrupt_parameter *parameter = create_interrupt_parameter(NULL);
    expect_mutex_init_deinit();
    protocol_translator_callbacks_t pt_cbs;
    init_pt_cbs(&pt_cbs);
    start_client(parameter, &pt_cbs, -1);
    clean_interrupt_thread_and_parameter(parameter);
    mock().checkExpectations();
}

TEST(pt_client, test_start_client_and_shutdown_with_failing_dispatch)
{
    struct event_base *base = evbase_mock_new();
    struct interrupt_parameter *parameter = create_interrupt_parameter(base);

    expect_mutex_init_deinit();
    mock().expectOneCall("shutdown_handler")
            .withPointerParameter("connection", parameter->connection)
            .withPointerParameter("userdata", parameter->userdata);
    protocol_translator_callbacks_t pt_cbs;
    init_pt_cbs(&pt_cbs);
    start_client(parameter, &pt_cbs, -1);
    clean_interrupt_thread_and_parameter(parameter);
    mock().checkExpectations();
}

TEST(pt_client, test_setting_message_id_generator)
{
    pt_client_set_msg_id_generator(edge_default_generate_msg_id);
    mock().checkExpectations();
}

TEST(pt_client, test_setting_default_message_id_generator)
{
    pt_client_set_msg_id_generator(NULL);
    mock().checkExpectations();
}
