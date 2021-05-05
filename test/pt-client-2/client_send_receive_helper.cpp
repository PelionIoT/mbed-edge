#include "pt-client-2/client_send_receive_helper.h"
extern "C" {
#include "pt-client-2/pt_client_helper.h"
}
#include "edge-rpc/rpc.h"
#include "test-lib/mutex_helper.h"
#include "test-lib/msg_api_mocks.h"
#include "mbed-trace/mbed_trace.h"
#define TRACE_GROUP "csrhelper"

connection_id_t active_connection_id = PT_API_CONNECTION_ID_INVALID;
connection_t *active_connection = NULL;
protocol_translator_callbacks_t callbacks;

int32_t rpc_id_counter = 0;

void reset_rpc_id_counter()
{
    rpc_id_counter = 1;
}

char *test_msg_generate_id()
{
    char *id = NULL;
    (void) asprintf(&id, "%d", rpc_id_counter);
    rpc_id_counter++;
    return id;
}

ValuePointer *expect_outgoing_data_frame(const char *data)
{
    ValuePointer *value_pointer = new ValuePointer((const uint8_t *) data, strlen(data));
    mock().expectOneCall("test_write_function")
            .withParameterOfType("ValuePointer", "value", (const void *) value_pointer)
            .andReturnValue(0);
    return value_pointer;
}

void receive_incoming_data_frame_expectations()
{
    mh_expect_mutexing(&rpc_mutex);
}

void find_client_device_expectations()
{
    mh_expect_mutexing(&api_mutex);
}

void receive_incoming_data_frame(connection_t *active_connection, const char *data)
{
    pt_client_read_data(active_connection, (char *) data, strlen(data));
}

void expect_msg_api_message()
{
    mh_expect_mutexing(&api_mutex);
    mock().expectOneCall("msg_api_send_message").andReturnValue(true);
}

void expect_msg_api_message_sending_fails()
{
    mh_expect_mutexing(&api_mutex);
    mock().expectOneCall("msg_api_send_message").andReturnValue(false);
}

void process_event_loop_send_message(bool connection_found)
{
    event_loop_message_t *msg = mock_msg_api_pop_message();
    if (NULL == msg) {
        CHECK(1 != 1); // place breakpoint on this line for debugging
    }
    mh_expect_mutexing(&api_mutex);
    if (connection_found) {
        mh_expect_mutexing(&rpc_mutex);
    }
    CHECK(event_loop_send_message_callback == msg->callback);
    msg->callback(msg->data);
    free(msg);
}

void process_event_loop_send_response()
{
    event_loop_message_t *msg = mock_msg_api_pop_message();
    if (NULL == msg) {
        CHECK(1 != 1); // place breakpoint on this line for debugging
    }
    CHECK(event_loop_send_response_callback == msg->callback);
    msg->callback(msg->data);
    free(msg);
}

int test_write_function(struct connection *connection, char *data, size_t len)
{
    tr_debug("test_write_function len: %lu data: '%.*s'\n", len, (int) len, data);
    ValuePointer *value_pointer = new ValuePointer((uint8_t *) data, len);
    int ret_val = mock().actualCall("test_write_function")
                          .withParameterOfType("ValuePointer", "value", (void *) value_pointer)
                          .returnIntValue();
    delete value_pointer;
    free(data);
    return ret_val;
}

connection_id_t create_client_connection()
{
    mock().expectOneCall("evthread_use_pthreads").andReturnValue(0);
    CHECK(0 == pt_api_init());
    pt_client_t *client = (pt_client_t *) calloc(1, sizeof(pt_client_t));

    connection_t *connection = connection_init(client);
    connection->client = client;
    connection->client->devices = pt_devices_create(client);

    initialize_callbacks(&callbacks);
    connection->client->protocol_translator_callbacks = &callbacks;

    connection->connected = true;
    connection->transport_connection = (transport_connection_t *) calloc(1, sizeof(transport_connection_t));
    connection->transport_connection->transport = NULL;
    connection->transport_connection->write_function = test_write_function;
    active_connection = connection;
    return connection->id;
}

void destroy_connection(connection_t *connection)
{
    CHECK(NULL != connection);
    free(connection->transport_connection);
    connection_destroy(connection);
    active_connection_id = PT_API_CONNECTION_ID_INVALID;
}

pt_client_t *destroy_active_connection()
{
    connection_t *connection = find_connection(active_connection_id);
    pt_client_t *client = connection->client;
    destroy_connection(connection);
    active_connection = NULL;
    return client;
}

void destroy_client(pt_client_t *client)
{
    if (active_connection) {
        active_connection->client = NULL;
    }
    if (client) {
        pt_client_free(client);
    }
}

void free_client_and_connection(connection_id_t connection_id)
{
    if (connection_id != PT_API_CONNECTION_ID_INVALID) {
        connection_t *connection = find_connection(connection_id);
        pt_client_t *client = connection->client;
        destroy_client(client);
        destroy_connection(connection);
        active_connection = NULL;
    } else {
        tr_warn("free_client_and_connection called when no active connection");
    }
}

