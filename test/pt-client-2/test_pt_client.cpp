#include <stdint.h>

#include "CppUTest/TestHarness.h"
#include "CppUTestExt/MockSupport.h"

#include "test-lib/msg_api_mocks.h"
#include "test-lib/mutex_helper.h"
extern "C" {
#include "common/edge_mutex.h"
#include "test-lib/evbase_mock.h"
#include "libwebsocket-mock/lws_mock.h"
#include "pt-client-2/pt_api_internal.h"
#include "pt-client-2/pt_client_api.h"
#include "pt-client-2/pt_client_helper.h"
#include "edge-rpc/rpc_timeout_api.h"
}

TEST_GROUP(pt_client_2){
    void setup()
    {
        CHECK_EQUAL(0, mock_msg_api_messages_in_queue());
    }

    void teardown()
    {
        mock_msg_api_wipeout_messages();
    }
};

TEST(pt_client_2, test_pt_api_init_fails)
{
    mock().expectOneCall("evthread_use_pthreads").andReturnValue(1);
    int rc = pt_api_init();
    CHECK(1 == rc);
    mock().checkExpectations();
}

TEST(pt_client_2, test_pt_api_init_succeeds)
{
    mock().expectOneCall("evthread_use_pthreads").andReturnValue(0);
    int rc = pt_api_init();
    CHECK(0 == rc);
    mock().checkExpectations();
}

TEST(pt_client_2, test_pt_client_create_callbacks_null)
{
    pt_client_t *client = pt_client_create(NULL, NULL);
    CHECK(NULL == client);
    mock().checkExpectations();
}

TEST(pt_client_2, test_pt_client_create_callbacks_empty_fields)
{
    protocol_translator_callbacks_t callbacks;
    initialize_callbacks(&callbacks);
    callbacks.connection_ready_cb = NULL;
    callbacks.connection_shutdown_cb = NULL;

    pt_client_t *client = pt_client_create(NULL, &callbacks);
    CHECK(NULL == client);

    callbacks.connection_ready_cb = test_connection_ready_cb;
    client = pt_client_create(NULL, &callbacks);
    CHECK(NULL == client);

    callbacks.connection_ready_cb = NULL;
    callbacks.connection_shutdown_cb = test_connection_shutdown_cb;
    client = pt_client_create(NULL, &callbacks);
    CHECK(NULL == client);
    mock().checkExpectations();
}

TEST(pt_client_2, test_pt_client_create_no_mutex)
{
    protocol_translator_callbacks_t callbacks;
    initialize_callbacks(&callbacks);

    pt_client_t *client = pt_client_create(NULL, &callbacks);
    CHECK(NULL == client);
    mock().checkExpectations();
}

TEST(pt_client_2, test_pt_client_create_null_socket_path)
{
    protocol_translator_callbacks_t callbacks;
    initialize_callbacks(&callbacks);

    pt_client_t *client = pt_client_create(NULL, &callbacks);
    CHECK(NULL == client);
    mock().checkExpectations();
}

TEST(pt_client_2, test_pt_client_start_client_is_null)
{
    pt_client_start(NULL, NULL, NULL, NULL, NULL);
    mock().checkExpectations();
}

TEST(pt_client_2, test_pt_client_start_name_is_null)
{
    protocol_translator_callbacks_t callbacks;
    initialize_callbacks(&callbacks);
    pt_client_t *client = pt_client_create("/tmp/test-socket-path", &callbacks);
    CHECK(NULL != client);
    CHECK(NULL != pt_client_get_devices(client));

    pt_client_start(client, NULL, NULL, NULL, NULL);

    pt_client_free(client);
    mock().checkExpectations();
}

TEST(pt_client_2, test_pt_client_start_null_success_and_failure_handler)
{
    protocol_translator_callbacks_t callbacks;
    initialize_callbacks(&callbacks);

    pt_client_t *client = create_client(&callbacks);
    CHECK(NULL != client);
    CHECK(NULL != pt_client_get_devices(client));

    pt_client_start(client, NULL, NULL, "test-name", NULL);

    pt_client_free(client);
    mock().checkExpectations();
}

TEST(pt_client_2, test_pt_client_start_null_success_handler)
{
    protocol_translator_callbacks_t callbacks;
    initialize_callbacks(&callbacks);

    pt_client_t *client = create_client(&callbacks);
    CHECK(NULL != client);
    CHECK(NULL != pt_client_get_devices(client));

    pt_client_start(client, NULL, test_failure_handler, "test-name", NULL);

    pt_client_free(client);
    mock().checkExpectations();
}

TEST(pt_client_2, test_pt_client_start_null_failure_handler)
{
    protocol_translator_callbacks_t callbacks;
    initialize_callbacks(&callbacks);

    pt_client_t *client = create_client(&callbacks);
    CHECK(NULL != client);
    CHECK(NULL != pt_client_get_devices(client));

    pt_client_start(client, test_success_handler, NULL, "test-name", NULL);

    pt_client_free(client);
    mock().checkExpectations();
}

TEST(pt_client_2, test_pt_client_start_null_ev_base)
{
    protocol_translator_callbacks_t callbacks;
    initialize_callbacks(&callbacks);

    pt_client_t *client = create_client(&callbacks);
    CHECK(NULL != client);
    CHECK(NULL != pt_client_get_devices(client));

    mock().expectOneCall("event_base_new").andReturnValue((void *) NULL);
    mock().expectOneCall("event_base_free").
        withParameter("base", (void *) NULL);
    mock().expectOneCall("libevent_global_shutdown");
    mh_expect_mutexing(&rpc_mutex);

    pt_client_start(client, test_success_handler, test_failure_handler, "test-name", NULL);
    pt_client_free(client);
    mock().checkExpectations();
}

TEST(pt_client_2, test_pt_client_start_initial_message_fails)
{
    protocol_translator_callbacks_t callbacks;
    initialize_callbacks(&callbacks);

    pt_client_t *client = create_client(&callbacks);
    CHECK(NULL != client);
    CHECK(NULL != pt_client_get_devices(client));

    struct event_base ev_base = {0};
    ev_base.event_loop_wait_simulation = false;

    mock().expectOneCall("event_base_new").andReturnValue(&ev_base);
    mock().expectOneCall("websocket_set_log_level_and_emit_function");
    struct event *timer_event = (struct event *) calloc(1, sizeof(struct event));
    timer_event->base = &ev_base;
    mock().expectOneCall("event_new")
            .withPointerParameter("base", &ev_base)
            .withIntParameter("fd", -1)
            .withIntParameter("flags", EV_PERSIST)
            .withPointerParameter("callback_fn", (void *) handle_timed_out_requests)
            .andReturnValue(timer_event);
    mock().expectOneCall("event_add").andReturnValue(0);

    mock().expectOneCall("msg_api_send_message").andReturnValue(false);
    mock().expectOneCall("event_del").withPointerParameter("ev", timer_event).andReturnValue(0);
    mock().expectOneCall("event_free").withPointerParameter("ev", timer_event);

    mock().expectOneCall("event_base_free").
        withParameter("base", &ev_base);
    mock().expectOneCall("libevent_global_shutdown");
    mh_expect_mutexing(&rpc_mutex);

    pt_client_start(client, test_success_handler, test_failure_handler, "test-name", NULL);
    pt_client_free(client);
    mock().checkExpectations();
    free(timer_event);
}

TEST(pt_client_2, test_pt_client_start_event_dispatch_fails)
{
    protocol_translator_callbacks_t callbacks;
    initialize_callbacks(&callbacks);

    pt_client_t *client = create_client(&callbacks);
    CHECK(NULL != client);
    CHECK(NULL != pt_client_get_devices(client));

    struct event_base ev_base = {0};
    ev_base.event_loop_wait_simulation = false;
    mock().expectOneCall("event_base_new").andReturnValue(&ev_base);
    mock().expectOneCall("websocket_set_log_level_and_emit_function");
    struct event *timer_event = (struct event *) calloc(1, sizeof(struct event));
    timer_event->base = &ev_base;
    mock().expectOneCall("event_new")
            .withPointerParameter("base", &ev_base)
            .withIntParameter("fd", -1)
            .withIntParameter("flags", EV_PERSIST)
            .withPointerParameter("callback_fn", (void *) handle_timed_out_requests)
            .andReturnValue(timer_event);
    mock().expectOneCall("event_add").andReturnValue(0);

    mock().expectOneCall("msg_api_send_message").andReturnValue(true);
    mock().expectOneCall("event_base_dispatch").withParameter("base", &ev_base).andReturnValue(1);
    mock().expectOneCall("event_base_free").withParameter("base", &ev_base);
    mock().expectOneCall("libevent_global_shutdown");
    mh_expect_mutexing(&rpc_mutex);
    mock().expectOneCall("event_del").withPointerParameter("ev", timer_event).andReturnValue(0);
    mock().expectOneCall("event_free").withPointerParameter("ev", timer_event);

    pt_client_start(client, test_success_handler, test_failure_handler, "test-name", NULL);
    pt_client_free(client);
    mock().checkExpectations();
    free(timer_event);
}

TEST(pt_client_2, test_pt_client_start)
{
    protocol_translator_callbacks_t callbacks;
    initialize_callbacks(&callbacks);

    pt_client_t *client = create_client(&callbacks);
    client->name = strdup("name, that gets freed.");
    CHECK(NULL != client);
    CHECK(NULL != pt_client_get_devices(client));

    struct event_base ev_base = {0};
    ev_base.event_loop_wait_simulation = false;
    mock().expectOneCall("event_base_new").andReturnValue(&ev_base);
    mock().expectOneCall("websocket_set_log_level_and_emit_function");

    struct event *timer_event = (struct event *) calloc(1, sizeof(struct event));
    timer_event->base = &ev_base;
    mock().expectOneCall("event_new")
            .withPointerParameter("base", &ev_base)
            .withIntParameter("fd", -1)
            .withIntParameter("flags", EV_PERSIST)
            .withPointerParameter("callback_fn", (void *) handle_timed_out_requests)
            .andReturnValue(timer_event);
    mock().expectOneCall("event_add").andReturnValue(0);

    mock().expectOneCall("msg_api_send_message").andReturnValue(true);
    mock().expectOneCall("event_base_dispatch").withParameter("base", &ev_base).andReturnValue(0);

    mock().expectOneCall("event_del").withPointerParameter("ev", timer_event).andReturnValue(0);
    mock().expectOneCall("event_free").withPointerParameter("ev", timer_event);
    mock().expectOneCall("event_base_free").
        withParameter("base", &ev_base);
    mock().expectOneCall("libevent_global_shutdown");
    mh_expect_mutexing(&rpc_mutex);

    pt_client_start(client, test_success_handler, test_failure_handler, "test-name", NULL);
    pt_client_free(client);
    mock().checkExpectations();
    free(timer_event);
}

TEST(pt_client_2, test_create_connection_cb_already_closed)
{
    mock().expectOneCall("evthread_use_pthreads").andReturnValue(0);
    CHECK(0 == pt_api_init());

    pt_client_t client;
    client.close_client = true;
    mh_expect_mutexing(&api_mutex);
    create_connection_cb(&client);
    mock().checkExpectations();
}

TEST(pt_client_2, test_create_connection_cb)
{
    mock().expectOneCall("evthread_use_pthreads").andReturnValue(0);
    CHECK(0 == pt_api_init());

    struct lws_context *lws_ctx = (struct lws_context*) malloc(sizeof(struct lws_context));
    struct lws lws;

    mock().expectOneCall("lws_create_context").andReturnValue(lws_ctx);
    mock().expectOneCall("lws_client_connect_via_info")
        .withStringParameter("path", "/1/pt")
        .andReturnValue(&lws);

    protocol_translator_callbacks_t callbacks;
    initialize_callbacks(&callbacks);
    pt_client_t *client = create_client(&callbacks);

    client->close_client = false;
    mh_expect_mutexing(&api_mutex);
    create_connection_cb(client);

    struct event_base ev_base = {0};
    ev_base.event_loop_started = false;
    ev_base.event_loop_wait_simulation = true;
    client->ev_base = &ev_base;
    mock().expectOneCall("lws_context_destroy");
    mock().expectOneCall("event_base_loopexit").withParameter("base", &ev_base)
        .withParameter("tv", (void *) NULL)
        .andReturnValue(0);
    client->close_client = true;
    destroy_connection_and_restart_reconnection_timer(find_connection(client->connection_id));

    pt_client_free(client);
    mock().checkExpectations();
}

TEST(pt_client_2, test_create_connection_cb_websocket_create_fails_and_succeeds)
{
    mock().expectOneCall("evthread_use_pthreads").andReturnValue(0);
    CHECK(0 == pt_api_init());

    protocol_translator_callbacks_t callbacks;
    initialize_callbacks(&callbacks);
    pt_client_t *client = create_client(&callbacks);
    client->close_client = false;

    mock().expectOneCall("lws_create_context").andReturnValue((void *) NULL);
    mock().expectOneCall("lws_context_destroy");
    mock().expectOneCall("msg_api_send_message_after_timeout_in_ms")
        .andReturnValue(true);

    mh_expect_mutexing(&api_mutex);
    create_connection_cb(client);
    pt_client_free(client);
    mock().checkExpectations();
}

TEST(pt_client_2, test_pt_client_shutdown_success)
{
    protocol_translator_callbacks_t callbacks;
    initialize_callbacks(&callbacks);
    pt_client_t *client = create_client(&callbacks);

    mock().expectOneCall("msg_api_send_message").andReturnValue(true);
    CHECK(PT_STATUS_SUCCESS == pt_client_shutdown(client));

    pt_client_free(client);
    mock().checkExpectations();
}

TEST(pt_client_2, test_pt_client_no_client)
{
    CHECK(PT_STATUS_ERROR == pt_client_shutdown(NULL));

    mock().checkExpectations();
}

TEST(pt_client_2, test_pt_client_shutdown_failure)
{
    protocol_translator_callbacks_t callbacks;
    initialize_callbacks(&callbacks);
    pt_client_t *client = create_client(&callbacks);

    mock().expectOneCall("msg_api_send_message").andReturnValue(false);
    CHECK(PT_STATUS_ERROR == pt_client_shutdown(client));

    pt_client_free(client);
    mock().checkExpectations();
}

TEST(pt_client_2, test_pt_client_shutdown_cb_connection_found_and_ok)
{
    protocol_translator_callbacks_t callbacks;
    initialize_callbacks(&callbacks);
    pt_client_t *client = create_client(&callbacks);

    mock().expectOneCall("evthread_use_pthreads");
    pt_api_init();

    struct lws_context *lws_ctx = (struct lws_context *) malloc(sizeof(struct lws_context));
    struct lws lws;
    mock().expectOneCall("lws_create_context").andReturnValue(lws_ctx);
    mock().expectOneCall("lws_client_connect_via_info").withStringParameter("path", "/1/pt").andReturnValue(&lws);
    create_client_connection(client);

    mock().expectOneCall("lws_callback_on_writable");
    mh_expect_mutexing(&api_mutex);
    pt_client_shutdown_cb(client);

    mock().expectOneCall("lws_context_destroy");
    connection_t *connection = find_connection(client->connection_id);
    transport_connection_t *transport_connection = connection->transport_connection;
    websocket_connection_t *websocket_conn = (websocket_connection_t *) transport_connection->transport;
    websocket_connection_t_destroy(&websocket_conn);
    transport_connection_t_destroy(&transport_connection);
    connection_destroy(connection);

    pt_client_free(client);
    mock().checkExpectations();
}

TEST(pt_client_2, test_pt_client_shutdown_cb_connection_found_and_no_websocket_connection)
{
    protocol_translator_callbacks_t callbacks;
    initialize_callbacks(&callbacks);
    pt_client_t *client = create_client(&callbacks);

    mock().expectOneCall("evthread_use_pthreads");
    pt_api_init();

    connection_t *connection = connection_init(client);
    client->connection_id = get_connection_id(connection);

    mh_expect_mutexing(&api_mutex);
    pt_client_shutdown_cb(client);

    connection_destroy(connection);
    pt_client_free(client);
    mock().checkExpectations();
}

TEST(pt_client_2, test_pt_client_shutdown_cb_no_connections)
{
    protocol_translator_callbacks_t callbacks;
    initialize_callbacks(&callbacks);
    pt_client_t *client = create_client(&callbacks);

    mh_expect_mutexing(&api_mutex);
    pt_client_shutdown_cb(client);

    pt_client_free(client);
    mock().checkExpectations();
}

char *test_generate_msg_id()
{
    return (char *) "STATIC-ID";
}

TEST(pt_client_2, test_pt_client_set_msg_id_generator)
{
    pt_client_t client;
    pt_client_set_msg_id_generator(&client, NULL);
    pt_client_set_msg_id_generator(&client, test_generate_msg_id);
    mock().checkExpectations();
}

TEST(pt_client_2, test_pt_client_get_connection_id)
{
    pt_client_t client;
    client.connection_id = 0;
    CHECK(0 == pt_client_get_connection_id(&client));
    mock().checkExpectations();
}

TEST(pt_client_2, test_default_check_close_condition)
{
    pt_client_t client;
    CHECK(default_check_close_condition(&client, true));
    CHECK(!default_check_close_condition(&client, false));
    mock().checkExpectations();
}

TEST(pt_client_2, test_pt_client_write_data_success)
{
    websocket_connection_t ws_connection;
    transport_connection_t transport_connection;
    transport_connection.transport = &ws_connection;
    connection_t connection;
    connection.transport_connection = &transport_connection;
    const char *data = "Data.";

    mock().expectOneCall("send_to_websocket").andReturnValue(0);
    CHECK(0 == pt_client_write_data(&connection, (char *) data, strlen(data)));
    mock().checkExpectations();
}

TEST(pt_client_2, test_pt_client_write_data_failure)
{
    websocket_connection_t ws_connection;
    transport_connection_t transport_connection;
    transport_connection.transport = &ws_connection;
    connection_t connection;
    connection.transport_connection = &transport_connection;
    const char *data = "Data.";

    mock().expectOneCall("send_to_websocket").andReturnValue(1);
    CHECK(1 == pt_client_write_data(&connection, (char *) data, strlen(data)));
    mock().checkExpectations();
}

int test_method(json_t *request, json_t *json_params, json_t **result, void *userdata)
{
    *result = json_string("test_method_result");
    return mock().actualCall("test_method")
        .returnIntValue();
}

static int test_write_function(connection_t *connection, char *data, size_t len)
{
    int rc = mock().actualCall("test_write_function").returnIntValue();
    printf("test_write_function: %.*s\n", (int) len, data);
    free(data);
    return rc;
}

struct jsonrpc_method_entry_t test_method_table[] = {
    {"test", test_method, NULL},
    {NULL, NULL, "o"}
};

TEST(pt_client_2, test_pt_client_read_data_success)
{
    char *data = (char *) "{\"jsonrpc\":\"2.0\", \"id\":\"90\",\"method\":\"test\"}";
    transport_connection_t transport_connection;
    transport_connection.write_function = test_write_function;
    pt_client_t client;
    client.method_table = test_method_table;
    connection_t connection;
    connection.client = &client;
    connection.transport_connection = &transport_connection;

    mock().expectOneCall("test_method").andReturnValue(0);
    mock().expectOneCall("test_write_function").andReturnValue(0);
    CHECK(0 == pt_client_read_data(&connection, data, strlen(data)));
    mock().checkExpectations();
}

TEST(pt_client_2, test_pt_client_read_data_protocol_error)
{
    char *data = (char *) "{\"jsonrpc\":\"2.0\", \"id\":\"90\",\"method\":\"test\"}BROKEN_MSG";
    transport_connection_t transport_connection;
    transport_connection.write_function = test_write_function;
    pt_client_t client;
    client.method_table = test_method_table;
    connection_t connection;
    connection.client = &client;
    connection.transport_connection = &transport_connection;

    CHECK(1 == pt_client_read_data(&connection, data, strlen(data)));
    mock().checkExpectations();
}

TEST(pt_client_2, test_pt_client_read_data_failure)
{
    char *data = (char *) "{\"jsonrpc\":\"2.0\", \"id\":\"90\",\"method\":\"test\"}";
    transport_connection_t transport_connection;
    transport_connection.write_function = test_write_function;
    pt_client_t client;
    client.method_table = test_method_table;
    connection_t connection;
    connection.client = &client;
    connection.transport_connection = &transport_connection;

    mock().expectOneCall("test_method").andReturnValue(0);
    mock().expectOneCall("test_write_function").andReturnValue(1);
    CHECK(2 == pt_client_read_data(&connection, data, strlen(data)));
    mock().checkExpectations();
}

TEST(pt_client_2, test_pt_client_disconnected_cb_close_flag_set)
{

    struct event_base ev_base = {0};
    ev_base.event_loop_started = false;
    pt_client_t client;
    client.close_client = true;
    client.close_condition_impl = default_check_close_condition;
    client.ev_base = &ev_base;

    mh_expect_mutexing(&api_mutex);
    mock().expectOneCall("event_base_loopexit")
        .withPointerParameter("base", &ev_base)
        .withPointerParameter("tv", NULL);
    pt_client_disconnected_cb(&client);
    mock().checkExpectations();
}

TEST(pt_client_2, test_pt_client_disconnected_cb_restart_connection_timer)
{

    pt_client_t client;
    client.close_client = false;
    client.reconnection_triggered = false;
    client.tries = 0;
    client.backoff_time_in_sec = 0;
    client.close_condition_impl = default_check_close_condition;

    // run reconnection attempts
    for (int i = 0; i < 6; i++) {
        mh_expect_mutexing(&api_mutex);
        mock().expectOneCall("msg_api_send_message_after_timeout_in_ms").andReturnValue(true);

        client.reconnection_triggered = false;
        pt_client_disconnected_cb(&client);
        int tries = i < 5 ? (i + 1) : 5;
        CHECK(tries == client.tries);
        int backoff_time = i < 5 ? (i + 1) * 1 : 5;
        CHECK(backoff_time == client.backoff_time_in_sec);
    }

    // run with reconnection_triggered = true
    CHECK(client.reconnection_triggered);
    mh_expect_mutexing(&api_mutex);
    pt_client_disconnected_cb(&client);
    mock().checkExpectations();
}

TEST(pt_client_2, test_pt_client_disconnected_cb_destroy_connection_and_restart)
{

    pt_client_t client;
    client.close_client = false;
    client.reconnection_triggered = true;
    client.close_condition_impl = default_check_close_condition;

    mock().expectOneCall("evthread_use_pthreads").andReturnValue(0);
    CHECK(0 == pt_api_init());

    struct lws_context *lws_ctx = (struct lws_context *) malloc(sizeof(struct lws_context));
    struct lws lws;
    mock().expectOneCall("lws_create_context").andReturnValue(lws_ctx);
    mock().expectOneCall("lws_client_connect_via_info").withStringParameter("path", "/1/pt").andReturnValue(&lws);
    create_client_connection(&client);

    mh_expect_mutexing(&api_mutex);
    mock().expectOneCall("lws_context_destroy");

    pt_client_disconnected_cb(&client);
    mock().checkExpectations();
}

TEST(pt_client_2, test_websocket_disconnected_no_connection)
{
    websocket_connection_t websocket_connection;
    websocket_connection.conn = NULL;
    websocket_disconnected(&websocket_connection);
    mock().checkExpectations();
}

TEST(pt_client_2, test_websocket_disconnected_connection_unable_to_send_message)
{
    protocol_translator_callbacks_t callbacks;
    initialize_callbacks(&callbacks);
    pt_client_t *client = create_client(&callbacks);

    connection_t connection;
    connection.connected = true;
    connection.client = client;
    websocket_connection_t websocket_connection;
    websocket_connection.conn = &connection;

    mh_expect_mutexing(&rpc_mutex);
    mock().expectOneCall("test_disconnected_cb");
    mock().expectOneCall("msg_api_send_message").andReturnValue(false);
    websocket_disconnected(&websocket_connection);

    CHECK(!connection.connected);

    pt_client_free(client);
    mock().checkExpectations();
}

TEST(pt_client_2, test_websocket_disconnected_connection)
{
    protocol_translator_callbacks_t callbacks;
    initialize_callbacks(&callbacks);
    pt_client_t *client = create_client(&callbacks);

    connection_t connection;
    connection.connected = true;
    connection.client = client;
    websocket_connection_t websocket_connection;
    websocket_connection.conn = &connection;

    mh_expect_mutexing(&rpc_mutex);
    mock().expectOneCall("test_disconnected_cb");
    mock().expectOneCall("msg_api_send_message").andReturnValue(true);
    websocket_disconnected(&websocket_connection);

    CHECK(!connection.connected);

    pt_client_free(client);
    mock().checkExpectations();
}

TEST(pt_client_2, test_websocket_connection_t_destroy)
{
    struct lws_context *lws_ctx = (struct lws_context *) malloc(sizeof(struct lws_context));
    websocket_connection_t *ws_connection = (websocket_connection_t *) malloc(sizeof(websocket_connection_t));
    ws_connection->lws_context = lws_ctx;

    websocket_message_list_t *ws_msg_list = (websocket_message_list_t *) malloc(sizeof(websocket_message_list_t));
    ws_connection->sent = ws_msg_list;
    ns_list_init(ws_connection->sent);

    websocket_message_t *msg_1 = (websocket_message_t *) malloc(sizeof(websocket_message_t));
    msg_1->bytes = (uint8_t *) strdup("msg_1");
    websocket_message_t *msg_2 = (websocket_message_t *) malloc(sizeof(websocket_message_t));
    msg_2->bytes = (uint8_t *) strdup("msg_2");

    ns_list_add_to_end(ws_msg_list, msg_1);
    ns_list_add_to_end(ws_msg_list, msg_2);

    mock().expectOneCall("lws_context_destroy");
    websocket_connection_t_destroy(&ws_connection);
    mock().checkExpectations();
}
