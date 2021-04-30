extern "C" {
#include "common/websocket_comm.h"
#include "libwebsockets.h"
#include <assert.h>
#include "edge-core/protocol_api_internal.h"
#include "edge-core/websocket_serv.h"
#include "libwebsocket-mock/lws_mock.h"
#include "test-lib/server_test.h"

struct connection *server_test_establish_connection()
{
    struct lws *wsi = lws_mock_create_wsi();
    lws_mock_connection_established(wsi, LWS_CALLBACK_ESTABLISHED);
    websocket_connection_t *websocket_connection = (websocket_connection_t *) wsi->userdata;
    return websocket_connection->conn;
}

int server_test_connection_filter_cb(const char *uri)
{
    struct lws *wsi = lws_mock_create_wsi();
    return lws_mock_callback(wsi, LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION);
}

void server_test_free_established_connection(struct connection *connection)
{
    websocket_connection_t *websocket_connection = (websocket_connection_t *)
                                                           connection->transport_connection->transport;
    websocket_server_connection_destroy(websocket_connection);
    if (websocket_connection && websocket_connection->wsi) {
        lws_mock_destroy_wsi(websocket_connection->wsi);
    }
}

void server_test_connection_closed(struct connection *connection)
{
    lws_mock_connection_closed(((websocket_connection_t *) (connection->transport_connection->transport))->wsi);
}

void server_test_call_receive_cb(struct connection *connection, void *data, size_t len)
{
    lws_mock_call_receive_cb(((websocket_connection_t *) (connection->transport_connection->transport))->wsi,
                             data,
                             len);
}
} // extern "C"
