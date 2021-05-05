#include "CppUTest/TestHarness.h"


extern "C" {
#include "common/websocket_comm.h"

    /**
     * Test definitions
     */
TEST_GROUP(websocket_comm) {
    void setup()
    {
    }

    void teardown()
    {
    }
};

TEST(websocket_comm, test_complete_message)
{
    websocket_connection_t *wsconn = (websocket_connection_t*) malloc(sizeof(websocket_connection_t));
    wsconn->msg = NULL;
    wsconn->msg_len = 0;
    uint8_t *fragment = (uint8_t*) "{}";
    size_t fragment_len = strlen((char*) fragment);
    CHECK_EQUAL(0, websocket_add_msg_fragment(wsconn, fragment, fragment_len));
    CHECK_EQUAL(fragment_len, wsconn->msg_len);
    MEMCMP_EQUAL("{}", wsconn->msg, fragment_len);
    websocket_reset_message(wsconn);
    free(wsconn);
}

TEST(websocket_comm, test_fragmented_message)
{
    websocket_connection_t *wsconn = (websocket_connection_t*) malloc(sizeof(websocket_connection_t));
    wsconn->msg = NULL;
    wsconn->msg_len = 0;
    uint8_t *fragment = (uint8_t*) "{}";
    size_t fragment_len = strlen((char*) fragment);
    CHECK_EQUAL(0, websocket_add_msg_fragment(wsconn, fragment, fragment_len));
    CHECK_EQUAL(fragment_len, wsconn->msg_len);

    CHECK_EQUAL(0, websocket_add_msg_fragment(wsconn, fragment, fragment_len));
    CHECK_EQUAL(2 * fragment_len, wsconn->msg_len);
    MEMCMP_EQUAL("{}{}", wsconn->msg, 2 * fragment_len);
    websocket_reset_message(wsconn);
    free(wsconn);
}

} // extern "C"
