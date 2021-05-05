#include "CppUTest/TestHarness.h"
#include "CppUTestExt/MockSupport.h"
extern "C" {
#include "edge-core/edge_server.h"
#include "edge-core/server.h"
#include "test-lib/evbase_mock.h"
#include "edge-core/websocket_serv.h"
#include "common/websocket_comm.h"
#include "libwebsocket-mock/lws_mock.h"
#include "libwebsockets.h"
}
#define TEST_UNIX_SOCKET_PATH "test_unix_socket"
#define TEST_LOCK_FILE_DESCRIPTOR_ID 20202

static int callback_lws_test(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len);

static struct lws_protocols protocols[] = {{
                                                   "edge_protocol_translator",
                                                   callback_lws_test,
                                                   sizeof(struct websocket_connection),
                                                   2048,
                                           },
                                           {NULL, NULL, 0, 0}};
struct lws_context *lwsc = NULL;
static int callback_lws_test(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len)
{
    mock().actualCall("callback_lws_test")
            .withUnsignedIntParameter("reason", reason);
    return 0;
}

TEST_GROUP(websocket_serv)
{
    void setup()
    {
        int lock_fd = TEST_LOCK_FILE_DESCRIPTOR_ID;
        int output_lock_fd = 0;
        create_program_context_and_data();
        mock().expectOneCall("edge_io_acquire_lock_for_socket")
                .withStringParameter("path", TEST_UNIX_SOCKET_PATH)
                .withOutputParameterReturning("lock_fd", &lock_fd, sizeof(int))
                .andReturnValue(true);
        mock().expectOneCall("edge_io_file_exists")
                .withStringParameter("path", TEST_UNIX_SOCKET_PATH)
                .andReturnValue(false);
        mock().expectOneCall("lws_create_context");
        lwsc = initialize_libwebsocket_context(NULL, TEST_UNIX_SOCKET_PATH, protocols, &output_lock_fd);
    }

    void teardown()
    {
        mock().expectOneCall("lws_context_destroy");
        lws_context_destroy(lwsc);
        free_program_context_and_data();
    }
};

TEST(websocket_serv, test_websocket_connection_destroy)
{
#define MSG_LEN 100
    websocket_connection_t *connection = (websocket_connection_t *) calloc(1, sizeof(websocket_connection_t));
    websocket_server_connection_initialize(connection);
    connection->to_close = true;
    struct lws *wsi = (struct lws *) calloc(1, sizeof(struct lws));
    wsi->protocol = &protocols[0];
    mock().expectOneCall("callback_lws_test")
            .withUnsignedIntParameter("reason", LWS_CALLBACK_ESTABLISHED);
    lws_mock_connection_established(wsi, LWS_CALLBACK_ESTABLISHED);
    connection->wsi = wsi;
    mock().expectOneCall("lws_callback_on_writable").andReturnValue(0);
    mock().expectOneCall("callback_lws_test").withUnsignedIntParameter("reason", LWS_CALLBACK_SERVER_WRITEABLE);
    uint8_t *bytes = (uint8_t *) calloc(1, 100);

    int len = 100;
    send_to_websocket(bytes, len, connection);

    websocket_server_connection_destroy(connection);
    free(connection);
    free(wsi);
    mock().checkExpectations();
}
