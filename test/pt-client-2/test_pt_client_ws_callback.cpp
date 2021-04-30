#include "CppUTest/TestHarness.h"
#include "CppUTestExt/MockSupport.h"

#include "test-lib/msg_api_mocks.h"
#include "test-lib/mutex_helper.h"
#include "cpputest-custom-types/value_pointer.h"
extern "C" {
#include "pt-client-2/pt_client_helper.h"
#include "libwebsocket-mock/lws_mock.h"
#include "pt-client-2/pt_api_internal.h"
#include "pt-client-2/pt_client_api.h"
}

TEST_GROUP(pt_client_2_ws_callback)
{
    void setup() {
        CHECK_EQUAL(0, mock_msg_api_messages_in_queue());
    }

    void teardown()
    {
        mock_msg_api_wipeout_messages();
        mh_expect_mutexing(&rpc_mutex);
        rpc_destroy_messages();
    }
};

static void test_connection_ready_cb_ws_callback(connection_id_t connection_id, const char *name, void *userdata)
{
    mock().actualCall("test_connection_ready_cb_ws_callback")
        .withIntParameter("connection_id", connection_id)
        .withStringParameter("name", name)
        .withPointerParameter("userdata", userdata);
}

static void test_connection_shutdown_cb_ws_callback(connection_id_t connection_id, void *userdata)
{
    // no-op
}

static void test_disconnected_cb_ws_callback(connection_id_t connection_id, void *userdata)
{
    mock().actualCall("test_disconnected_cb_ws_callback");
}

static void test_failure_handler_ws_callback(void *userdata)
{
    mock().actualCall("test_failure_handler_ws_callback");
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

int test_write_function_ws_callback(connection_t *connection, char *data, size_t len)
{
    int rc = mock().actualCall("test_write_function_ws_callback").returnIntValue();
    printf("test_write_function_ws_callback: %.*s\n", (int) len, data);
    free(data);
    return rc;
}

TEST(pt_client_2_ws_callback, test_default_case)
{
    // Shall got to default case.
    lws_callback_reasons reason = LWS_CALLBACK_VHOST_CERT_UPDATE;
    struct lws lws;
    mock().expectOneCall("websocket_lws_callback_reason")
        .andReturnValue("test");
    CHECK(0 == callback_edge_client_protocol_translator(&lws, reason, NULL, NULL, 0));
    mock().checkExpectations();
}

TEST(pt_client_2_ws_callback, test_client_established_msg_succeeds)
{
    lws_callback_reasons reason = LWS_CALLBACK_CLIENT_ESTABLISHED;
    struct lws lws;

    mock().expectOneCall("evthread_use_pthreads").andReturnValue(0);
    CHECK(0 == pt_api_init());

    protocol_translator_callbacks_t callbacks;
    initialize_callbacks(&callbacks);
    callbacks.connection_ready_cb = test_connection_ready_cb_ws_callback;
    callbacks.connection_shutdown_cb = test_connection_shutdown_cb_ws_callback;

    pt_client_t *client = create_client(&callbacks);
    client->name = strdup("client-name");
    client->success_handler = pt_register_success_cb;
    client->failure_handler = pt_register_failure_cb;
    char *char_userdata = (char *) "userdata";
    client->userdata = char_userdata;

    websocket_connection_t ws_connection;
    connection_t *connection = connection_init(client);
    transport_connection_t transport;
    transport.write_function = test_write_function_ws_callback;
    ws_connection.conn = connection;
    connection->transport_connection = &transport;

    mock().expectOneCall("test_connection_ready_cb_ws_callback")
        .withIntParameter("connection_id", get_connection_id(connection))
        .withStringParameter("name", "client-name")
        .withPointerParameter("userdata", char_userdata);
    mh_expect_mutexing(&api_mutex); // pt_devices_set_all_to_unregistered_state
    mh_expect_mutexing(&api_mutex); // pt_api_send_to_event_loop
    mock().expectOneCall("msg_api_send_message").andReturnValue(true);

    CHECK(0 == callback_edge_client_protocol_translator(&lws, reason, &ws_connection, NULL, 0));
    CHECK(connection->connected);
    CHECK(NULL != client->generate_msg_id);

    // Pop messages from mock
    mh_expect_mutexing(&api_mutex);
    mh_expect_mutexing(&rpc_mutex);
    mock().expectOneCall("test_write_function_ws_callback");
    event_loop_message_t *msg = mock_msg_api_pop_message();
    msg->callback(msg->data);
    free(msg);

    pt_client_free(client);
    connection_destroy(connection);
    mock().checkExpectations();
}

TEST(pt_client_2_ws_callback, test_client_established_msg_fails)
{
    lws_callback_reasons reason = LWS_CALLBACK_CLIENT_ESTABLISHED;
    struct lws lws;

    mock().expectOneCall("evthread_use_pthreads").andReturnValue(0);
    CHECK(0 == pt_api_init());

    protocol_translator_callbacks_t callbacks;
    initialize_callbacks(&callbacks);
    callbacks.connection_ready_cb = test_connection_ready_cb_ws_callback;
    callbacks.connection_shutdown_cb = test_connection_shutdown_cb_ws_callback;

    pt_client_t *client = create_client(&callbacks);
    client->name = strdup("client-name");
    char *char_userdata = (char *) "userdata";
    client->userdata = char_userdata;
    client->failure_handler = test_failure_handler_ws_callback;

    websocket_connection_t ws_connection;
    connection_t *connection = connection_init(client);
    connection->id = -1;
    transport_connection_t transport;
    transport.write_function = test_write_function_ws_callback;
    ws_connection.conn = connection;
    connection->transport_connection = &transport;

    mock().expectOneCall("test_connection_ready_cb_ws_callback")
        .withIntParameter("connection_id", get_connection_id(connection))
        .withStringParameter("name", "client-name")
        .withPointerParameter("userdata", char_userdata);

    mh_expect_mutexing(&api_mutex); // pt_devices_set_all_to_unregistered_state

    mock().expectOneCall("test_failure_handler_ws_callback");
    CHECK(0 == callback_edge_client_protocol_translator(&lws, reason, &ws_connection, NULL, 0));
    CHECK(connection->connected);
    CHECK(NULL != client->generate_msg_id);

    pt_client_free(client);
    connection_destroy(connection);
    mock().checkExpectations();
}

TEST(pt_client_2_ws_callback, test_closed)
{
    lws_callback_reasons reason = LWS_CALLBACK_CLOSED;
    struct lws lws;

    mock().expectOneCall("evthread_use_pthreads").andReturnValue(0);
    CHECK(0 == pt_api_init());

    protocol_translator_callbacks_t callbacks;
    initialize_callbacks(&callbacks);
    callbacks.connection_ready_cb = test_connection_ready_cb_ws_callback;
    callbacks.connection_shutdown_cb = test_connection_shutdown_cb_ws_callback;
    callbacks.disconnected_cb = test_disconnected_cb_ws_callback;

    pt_client_t *client = create_client(&callbacks);
    client->name = strdup("client-name");
    char *char_userdata = (char *) "userdata";
    client->userdata = char_userdata;
    client->failure_handler = test_failure_handler_ws_callback;

    websocket_connection_t ws_connection;
    connection_t *connection = connection_init(client);
    ws_connection.conn = connection;

    mh_expect_mutexing(&rpc_mutex);
    mock().expectOneCall("test_disconnected_cb_ws_callback");
    mock().expectOneCall("msg_api_send_message").andReturnValue(true);
    CHECK(0 == callback_edge_client_protocol_translator(&lws, reason, &ws_connection, NULL, 0));
    CHECK(!connection->connected);

    pt_client_free(client);
    connection_destroy(connection);
    mock().checkExpectations();
}

TEST(pt_client_2_ws_callback, test_client_connnection_error)
{
    lws_callback_reasons reason = LWS_CALLBACK_CLIENT_CONNECTION_ERROR;
    struct lws lws;
    websocket_connection_t ws_connection;
    connection_t connection;
    protocol_translator_callbacks_t callbacks;
    initialize_callbacks(&callbacks);
    callbacks.connection_ready_cb = test_connection_ready_cb_ws_callback;
    callbacks.connection_shutdown_cb = test_connection_shutdown_cb_ws_callback;
    callbacks.disconnected_cb = test_disconnected_cb_ws_callback;

    pt_client_t *client = create_client(&callbacks);
    ws_connection.conn = &connection;
    connection.client = client;

    mh_expect_mutexing(&rpc_mutex);
    mock().expectOneCall("test_disconnected_cb_ws_callback");
    mock().expectOneCall("msg_api_send_message").andReturnValue(true);
    CHECK(0 == callback_edge_client_protocol_translator(&lws, reason, &ws_connection, NULL, 0));
    CHECK(!client->registered);
    CHECK(!connection.connected);

    pt_client_free(client);
    mock().checkExpectations();
}

TEST(pt_client_2_ws_callback, test_wsi_destroy)
{
    lws_callback_reasons reason = LWS_CALLBACK_WSI_DESTROY;
    struct lws lws;
    websocket_connection_t ws_connection;
    ws_connection.conn = NULL;

    CHECK(0 == callback_edge_client_protocol_translator(&lws, reason, &ws_connection, NULL, 0));
    mock().checkExpectations();
}

TEST(pt_client_2_ws_callback, test_client_writeable_close_connection_on)
{
    lws_callback_reasons reason = LWS_CALLBACK_CLIENT_WRITEABLE;
    struct lws lws;
    websocket_connection_t ws_connection;
    connection_t connection;

    protocol_translator_callbacks_t callbacks;
    initialize_callbacks(&callbacks);
    callbacks.connection_ready_cb = test_connection_ready_cb_ws_callback;
    callbacks.connection_shutdown_cb = test_connection_shutdown_cb_ws_callback;
    callbacks.disconnected_cb = test_disconnected_cb_ws_callback;

    pt_client_t *client = create_client(&callbacks);
    client->close_connection = true;

    ws_connection.conn = &connection;
    connection.client = client;

    mock().expectOneCall("lws_close_reason");
    CHECK(-1 == callback_edge_client_protocol_translator(&lws, reason, &ws_connection, NULL, 0));

    pt_client_free(client);
    mock().checkExpectations();
}

TEST(pt_client_2_ws_callback, test_client_writeable_close_connection_null_message)
{
    lws_callback_reasons reason = LWS_CALLBACK_CLIENT_WRITEABLE;
    struct lws lws;
    websocket_connection_t ws_connection;
    websocket_message_list_t ws_message_list;
    connection_t connection;

    protocol_translator_callbacks_t callbacks;
    initialize_callbacks(&callbacks);
    callbacks.connection_ready_cb = test_connection_ready_cb_ws_callback;
    callbacks.connection_shutdown_cb = test_connection_shutdown_cb_ws_callback;
    callbacks.disconnected_cb = test_disconnected_cb_ws_callback;

    pt_client_t *client = create_client(&callbacks);
    client->close_connection = false;

    ws_connection.conn = &connection;
    ws_connection.sent = &ws_message_list;
    ns_list_init(ws_connection.sent);
    connection.client = client;

    CHECK(0 == callback_edge_client_protocol_translator(&lws, reason, &ws_connection, NULL, 0));

    pt_client_free(client);
    mock().checkExpectations();
}

TEST(pt_client_2_ws_callback, test_client_writeable_close_connection_write_message)
{
    lws_callback_reasons reason = LWS_CALLBACK_CLIENT_WRITEABLE;
    struct lws lws;
    websocket_connection_t ws_connection;
    websocket_message_list_t ws_message_list;
    connection_t connection;

    protocol_translator_callbacks_t callbacks;
    initialize_callbacks(&callbacks);
    callbacks.connection_ready_cb = test_connection_ready_cb_ws_callback;
    callbacks.connection_shutdown_cb = test_connection_shutdown_cb_ws_callback;
    callbacks.disconnected_cb = test_disconnected_cb_ws_callback;

    pt_client_t *client = create_client(&callbacks);
    client->close_connection = false;

    ws_connection.conn = &connection;
    ws_connection.sent = &ws_message_list;
    ns_list_init(ws_connection.sent);
    connection.client = client;

    websocket_message_t msg_1;
    msg_1.bytes = (uint8_t *) "message-1";
    msg_1.len = strlen("message-1");
    ns_list_add_to_end(&ws_message_list, &msg_1);

    // Not handled in test, and not sent. This is to ensure that list size is counted
    // and lws_callback_on_writable is called for rest of the messages.
    websocket_message_t msg_2;
    ns_list_add_to_end(&ws_message_list, &msg_2);

    ValuePointer lws_write_msg_param_1 = ValuePointer(msg_1.bytes, msg_1.len);

    mock().expectOneCall("lws_write")
        .withParameterOfType("ValuePointer", "buf", &lws_write_msg_param_1)
        .andReturnValue(0);
    mock().expectOneCall("websocket_message_t_destroy");
    mock().expectOneCall("lws_callback_on_writable");

    CHECK(0 == callback_edge_client_protocol_translator(&lws, reason, &ws_connection, NULL, 0));

    pt_client_free(client);
    mock().checkExpectations();
}

TEST(pt_client_2_ws_callback, test_client_receive_read_data_fails)
{
    lws_callback_reasons reason = LWS_CALLBACK_CLIENT_RECEIVE;
    struct lws lws;
    websocket_connection_t ws_connection;
    ws_connection.wsi = &lws;
    transport_connection_t transport;
    transport.write_function = test_write_function_ws_callback;
    connection_t connection;
    ws_connection.conn = &connection;
    connection.transport_connection = &transport;
    transport.transport = &ws_connection;

    protocol_translator_callbacks_t callbacks;
    initialize_callbacks(&callbacks);
    callbacks.connection_ready_cb = test_connection_ready_cb_ws_callback;
    callbacks.connection_shutdown_cb = test_connection_shutdown_cb_ws_callback;
    callbacks.disconnected_cb = test_disconnected_cb_ws_callback;

    pt_client_t *client = create_client(&callbacks);
    client->method_table = NULL;
    client->close_connection = false;
    connection.client = client;

    char *msg_1 = (char *) "Message";
    char *msg_2 = (char *) " payload";
    size_t len_1 = strlen(msg_1);
    size_t len_2 = strlen(msg_2);

    mock().expectOneCall("websocket_add_msg_fragment").andReturnValue(0);
    mock().expectOneCall("lws_remaining_packet_payload").andReturnValue(len_1);
    mock().expectOneCall("lws_is_final_fragment").andReturnValue(0);

    mock().expectOneCall("websocket_add_msg_fragment").andReturnValue(0);
    mock().expectOneCall("lws_remaining_packet_payload").andReturnValue(len_2);
    mock().expectOneCall("lws_is_final_fragment").andReturnValue(1);

    CHECK(0 == callback_edge_client_protocol_translator(&lws, reason, &ws_connection, msg_1, len_1));

    // Emulate websocket connection object on fragmented messages
    ws_connection.msg = (uint8_t *) msg_1;
    ws_connection.msg_len = len_1;

    mock().expectOneCall("websocket_reset_message");
    mock().expectOneCall("lws_callback_on_writable");

    CHECK(0 == callback_edge_client_protocol_translator(&lws, reason, &ws_connection, msg_2, len_2));
    CHECK(client->close_connection);

    pt_client_free(client);
    mock().checkExpectations();
}

TEST(pt_client_2_ws_callback, test_client_receive_add_msg_fragment_fails)
{
    lws_callback_reasons reason = LWS_CALLBACK_CLIENT_RECEIVE;
    struct lws lws;
    websocket_connection_t ws_connection;
    ws_connection.wsi = &lws;
    transport_connection_t transport;
    transport.write_function = test_write_function_ws_callback;
    connection_t connection;
    ws_connection.conn = &connection;
    connection.transport_connection = &transport;
    transport.transport = &ws_connection;

    protocol_translator_callbacks_t callbacks;
    initialize_callbacks(&callbacks);
    callbacks.connection_ready_cb = test_connection_ready_cb_ws_callback;
    callbacks.connection_shutdown_cb = test_connection_shutdown_cb_ws_callback;
    callbacks.disconnected_cb = test_disconnected_cb_ws_callback;

    pt_client_t *client = create_client(&callbacks);
    client->method_table = NULL;
    client->close_connection = false;
    connection.client = client;

    char *msg = (char *) "Message";
    size_t len = strlen(msg);

    mock().expectOneCall("websocket_add_msg_fragment").andReturnValue(1);
    mock().expectOneCall("lws_callback_on_writable");

    CHECK(0 == callback_edge_client_protocol_translator(&lws, reason, &ws_connection, msg, len));
    CHECK(client->close_connection);

    pt_client_free(client);
    mock().checkExpectations();
}
