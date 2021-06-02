#include <stdint.h>

#include "CppUTest/TestHarness.h"
#include "CppUTestExt/MockSupport.h"

#include "test-lib/msg_api_mocks.h"
#include "test-lib/mutex_helper.h"
extern "C" {
#include "common/edge_mutex.h"
#include "pt-client-2/pt_crypto_api.h"
#include "pt-client-2/pt_crypto_api_internal.h"
#include "libwebsocket-mock/lws_mock.h"
#include "pt-client-2/pt_api_internal.h"
#include "pt-client-2/pt_client_api.h"
#include "pt-client-2/pt_client_helper.h"
#include "edge-rpc/rpc_timeout_api.h"
}
#include "pt-client-2/client_send_receive_helper.h"

TEST_GROUP(pt_crypto_api_2){
    void setup() {
        CHECK_EQUAL(0, mock_msg_api_messages_in_queue());
        reset_rpc_id_counter();
        rpc_set_generate_msg_id(test_msg_generate_id);

        mock_msg_api_wipeout_messages();
        active_connection_id = create_client_connection();
    }

    void teardown()
    {
        CHECK_EQUAL(0, mock_msg_api_messages_in_queue());
        free_client_and_connection(active_connection_id);
        active_connection_id = PT_API_CONNECTION_ID_INVALID;
    }
};

void get_item_success_handler(const connection_id_t connection_id,
                              const uint8_t *data,
                              const size_t size,
                              void *userdata)
{
    ValuePointer *data_pointer = new ValuePointer(data, size);
    mock().actualCall("get_item_success_handler")
      .withIntParameter("connection_id", connection_id)
      .withParameterOfType("ValuePointer", "data", (void *) data_pointer)
      .withPointerParameter("userdata", userdata);
    delete(data_pointer);
}

void get_item_failure_handler(const connection_id_t connection_id,
                              void *userdata)
{

    mock().actualCall("get_item_failure_handler")
      .withIntParameter("connection_id", connection_id)
      .withPointerParameter("userdata", userdata);
}

void crypto_failure_handler(const connection_id_t connection_id,
                            int errorcode,
                            void *userdata)
{

    mock().actualCall("crypto_failure_handler")
        .withIntParameter("connection_id", connection_id)
        .withIntParameter("errorcode", errorcode)
        .withPointerParameter("userdata", userdata);
}

TEST(pt_crypto_api_2, test_pt_crypto_success_with_data_invalid_parameters)
{
    pt_crypto_success_with_data(NULL, NULL, NULL);
}

TEST(pt_crypto_api_2, test_pt_crypto_success_invalid_parameters)
{
    pt_crypto_success(NULL, NULL);
}

TEST(pt_crypto_api_2, test_pt_crypto_get_certificate)
{
    const char *userdata = "dummy_userdata";

    pt_client_t *client = active_connection->client;
    client->userdata = (void *) userdata;

    expect_msg_api_message();
    ValuePointer *value_pointer = expect_outgoing_data_frame(
            "{\"id\":\"1\",\"jsonrpc\":\"2.0\",\"method\":\"crypto_get_certificate\",\"params\":{"
            "\"certificate\":\"DLMS\"}}");
    pt_status_t status = pt_crypto_get_certificate(active_connection_id,
                                                   "DLMS",
                                                   get_item_success_handler,
                                                   get_item_failure_handler,
                                                   (void *) userdata);
    CHECK_EQUAL(PT_STATUS_SUCCESS, status);
    process_event_loop_send_message(true /* connection found */);
    receive_incoming_data_frame_expectations();

    // cert value, passed to callback function: testcertdata
    // base64 encoded, in json rpc api: dGVzdGNlcnRkYXRh
    ValuePointer *cert_data_pointer = new ValuePointer((const uint8_t *)"testcertdata", strlen("testcertdata"));
    mock().expectOneCall("get_item_success_handler")
      .withIntParameter("connection_id", active_connection_id)
      .withParameterOfType("ValuePointer", "data", (const void *) cert_data_pointer)
      .withPointerParameter("userdata", (void *) userdata);
    receive_incoming_data_frame(active_connection, "{\"id\":\"1\",\"jsonrpc\":\"2.0\",\"result\":{\"certificate_name\":\"DLMS\", \"certificate_data\":\"dGVzdGNlcnRkYXRh\"}}");

    mock().checkExpectations();
    delete cert_data_pointer;
    delete value_pointer;
}

TEST(pt_crypto_api_2, test_pt_crypto_get_certificate_failure)
{
    const char *userdata = "dummy_userdata";

    pt_client_t *client = active_connection->client;
    client->userdata = (void *) userdata;

    expect_msg_api_message();
    ValuePointer *value_pointer = expect_outgoing_data_frame(
            "{\"id\":\"1\",\"jsonrpc\":\"2.0\",\"method\":\"crypto_get_certificate\",\"params\":{"
            "\"certificate\":\"DLMS\"}}");
    pt_status_t status = pt_crypto_get_certificate(active_connection_id,
                                                   "DLMS",
                                                   get_item_success_handler,
                                                   get_item_failure_handler,
                                                   (void *) userdata);
    CHECK_EQUAL(PT_STATUS_SUCCESS, status);
    process_event_loop_send_message(true /* connection found */);
    receive_incoming_data_frame_expectations();

    mock().expectOneCall("get_item_failure_handler")
      .withIntParameter("connection_id", active_connection_id)
      .withPointerParameter("userdata", (void *) userdata);
    receive_incoming_data_frame(active_connection,
                                "{\"id\":\"1\",\"jsonrpc\":\"2.0\",\"error\":{\"message\":\"Internal Error\","
                                "\"data\":\"Could not send crypto api event.\",\"code\":1}}");

    mock().checkExpectations();
    delete value_pointer;
}

TEST(pt_crypto_api_2, test_pt_crypto_get_certificate_response_missing_data_key)
{
    const char *userdata = "dummy_userdata";

    pt_client_t *client = active_connection->client;
    client->userdata = (void *) userdata;

    expect_msg_api_message();
    ValuePointer *value_pointer = expect_outgoing_data_frame(
            "{\"id\":\"1\",\"jsonrpc\":\"2.0\",\"method\":\"crypto_get_certificate\",\"params\":{"
            "\"certificate\":\"DLMS\"}}");
    pt_status_t status = pt_crypto_get_certificate(active_connection_id,
                                                   "DLMS",
                                                   get_item_success_handler,
                                                   get_item_failure_handler,
                                                   (void *) userdata);
    CHECK_EQUAL(PT_STATUS_SUCCESS, status);
    process_event_loop_send_message(true /* connection found */);
    receive_incoming_data_frame_expectations();

    mock().expectOneCall("get_item_failure_handler")
      .withIntParameter("connection_id", active_connection_id)
      .withPointerParameter("userdata", (void *) userdata);
    receive_incoming_data_frame(active_connection, "{\"id\":\"1\",\"jsonrpc\":\"2.0\",\"result\":{\"certificate_name\":\"DLMS\"}}");

    mock().checkExpectations();
    delete value_pointer;
}

TEST(pt_crypto_api_2, test_pt_crypto_get_certificate_response_empty_data_key)
{
    const char *userdata = "dummy_userdata";

    pt_client_t *client = active_connection->client;
    client->userdata = (void *) userdata;

    expect_msg_api_message();
    ValuePointer *value_pointer = expect_outgoing_data_frame(
            "{\"id\":\"1\",\"jsonrpc\":\"2.0\",\"method\":\"crypto_get_certificate\",\"params\":{"
            "\"certificate\":\"DLMS\"}}");
    pt_status_t status = pt_crypto_get_certificate(active_connection_id,
                                                   "DLMS",
                                                   get_item_success_handler,
                                                   get_item_failure_handler,
                                                   (void *) userdata);
    CHECK_EQUAL(PT_STATUS_SUCCESS, status);
    process_event_loop_send_message(true /* connection found */);
    receive_incoming_data_frame_expectations();

    mock().expectOneCall("get_item_failure_handler")
      .withIntParameter("connection_id", active_connection_id)
      .withPointerParameter("userdata", (void *) userdata);
    receive_incoming_data_frame(active_connection, "{\"id\":\"1\",\"jsonrpc\":\"2.0\",\"result\":{\"certificate_name\":\"DLMS\", \"certificate_data\":\"\"}}");

    mock().checkExpectations();
    delete value_pointer;
}

TEST(pt_crypto_api_2, test_pt_crypto_get_certificate_empty_name)
{
  const char *userdata = "dummy_userdata";

  pt_status_t status = pt_crypto_get_certificate(active_connection_id,
                                                 NULL,
                                                 get_item_success_handler,
                                                 get_item_failure_handler,
                                                 (void *) userdata);
  CHECK_EQUAL(PT_STATUS_INVALID_PARAMETERS, status);
}

TEST(pt_crypto_api_2, test_pt_crypto_get_certificate_missing_handlers)
{
  const char *userdata = "dummy_userdata";

  pt_status_t status = pt_crypto_get_certificate(active_connection_id,
                                                 "name",
                                                 get_item_success_handler,
                                                 NULL,
                                                 (void *) userdata);
  CHECK_EQUAL(PT_STATUS_ALLOCATION_FAIL, status);

  status = pt_crypto_get_certificate(active_connection_id,
                                     "name",
                                     NULL,
                                     get_item_failure_handler,
                                     (void *) userdata);
  CHECK_EQUAL(PT_STATUS_ALLOCATION_FAIL, status);

  status = pt_crypto_get_certificate(active_connection_id,
                                     "name",
                                     NULL,
                                     NULL,
                                     (void *) userdata);
  CHECK_EQUAL(PT_STATUS_ALLOCATION_FAIL, status);
}

TEST(pt_crypto_api_2, test_pt_crypto_get_public_key)
{
    const char *userdata = "dummy_userdata";

    pt_client_t *client = active_connection->client;
    client->userdata = (void *) userdata;

    expect_msg_api_message();
    ValuePointer *value_pointer = expect_outgoing_data_frame(
            "{\"id\":\"1\",\"jsonrpc\":\"2.0\",\"method\":\"crypto_get_public_key\",\"params\":{"
            "\"key\":\"DLMS\"}}");
    pt_status_t status = pt_crypto_get_public_key(active_connection_id,
                                                  "DLMS",
                                                  get_item_success_handler,
                                                  get_item_failure_handler,
                                                  (void *) userdata);
    CHECK_EQUAL(PT_STATUS_SUCCESS, status);
    process_event_loop_send_message(true /* connection found */);
    receive_incoming_data_frame_expectations();

    // key value, passed to callback function: testpublickey
    // base64 encoded, in json rpc api: dGVzdHB1YmxpY2tleQ==
    ValuePointer *key_data_pointer = new ValuePointer((const uint8_t *)"testpublickey", strlen("testpublickey"));
    mock().expectOneCall("get_item_success_handler")
      .withIntParameter("connection_id", active_connection_id)
      .withParameterOfType("ValuePointer", "data", (const void *) key_data_pointer)
      .withPointerParameter("userdata", (void *) userdata);
    receive_incoming_data_frame(active_connection, "{\"id\":\"1\",\"jsonrpc\":\"2.0\",\"result\":{\"key_name\":\"DLMS\", \"key_data\":\"dGVzdHB1YmxpY2tleQ==\"}}");

    mock().checkExpectations();
    delete key_data_pointer;
    delete value_pointer;
}

TEST(pt_crypto_api_2, test_pt_crypto_get_public_key_failure)
{
    const char *userdata = "dummy_userdata";

    pt_client_t *client = active_connection->client;
    client->userdata = (void *) userdata;

    expect_msg_api_message();
    ValuePointer *value_pointer = expect_outgoing_data_frame(
            "{\"id\":\"1\",\"jsonrpc\":\"2.0\",\"method\":\"crypto_get_public_key\",\"params\":{"
            "\"key\":\"DLMS\"}}");
    pt_status_t status = pt_crypto_get_public_key(active_connection_id,
                                                  "DLMS",
                                                  get_item_success_handler,
                                                  get_item_failure_handler,
                                                  (void *) userdata);
    CHECK_EQUAL(PT_STATUS_SUCCESS, status);
    process_event_loop_send_message(true /* connection found */);
    receive_incoming_data_frame_expectations();

    mock().expectOneCall("get_item_failure_handler")
      .withIntParameter("connection_id", active_connection_id)
      .withPointerParameter("userdata", (void *) userdata);
    receive_incoming_data_frame(active_connection,
                                "{\"id\":\"1\",\"jsonrpc\":\"2.0\",\"error\":{\"message\":\"Internal Error\","
                                "\"data\":\"Could not send crypto api event.\",\"code\":1}}");

    mock().checkExpectations();
    delete value_pointer;
}

TEST(pt_crypto_api_2, test_pt_crypto_get_public_key_missing_data_key)
{
    const char *userdata = "dummy_userdata";

    pt_client_t *client = active_connection->client;
    client->userdata = (void *) userdata;

    expect_msg_api_message();
    ValuePointer *value_pointer = expect_outgoing_data_frame(
            "{\"id\":\"1\",\"jsonrpc\":\"2.0\",\"method\":\"crypto_get_public_key\",\"params\":{"
            "\"key\":\"DLMS\"}}");
    pt_status_t status = pt_crypto_get_public_key(active_connection_id,
                                                  "DLMS",
                                                  get_item_success_handler,
                                                  get_item_failure_handler,
                                                  (void *) userdata);
    CHECK_EQUAL(PT_STATUS_SUCCESS, status);
    process_event_loop_send_message(true /* connection found */);
    receive_incoming_data_frame_expectations();

    mock().expectOneCall("get_item_failure_handler")
        .withIntParameter("connection_id", active_connection_id)
        .withPointerParameter("userdata", (void *) userdata);
    receive_incoming_data_frame(active_connection, "{\"id\":\"1\",\"jsonrpc\":\"2.0\",\"result\":{\"key_name\":\"DLMS\"}}");

    mock().checkExpectations();
    delete value_pointer;
}


TEST(pt_crypto_api_2, test_pt_crypto_get_public_key_empty_data_key)
{
    const char *userdata = "dummy_userdata";

    pt_client_t *client = active_connection->client;
    client->userdata = (void *) userdata;

    expect_msg_api_message();
    ValuePointer *value_pointer = expect_outgoing_data_frame(
                                                             "{\"id\":\"1\",\"jsonrpc\":\"2.0\",\"method\":\"crypto_get_public_key\",\"params\":{"
                                                             "\"key\":\"DLMS\"}}");
    pt_status_t status = pt_crypto_get_public_key(active_connection_id,
                                                  "DLMS",
                                                  get_item_success_handler,
                                                  get_item_failure_handler,
                                                  (void *) userdata);
    CHECK_EQUAL(PT_STATUS_SUCCESS, status);
    process_event_loop_send_message(true /* connection found */);
    receive_incoming_data_frame_expectations();

    ValuePointer *key_data_pointer = new ValuePointer((const uint8_t *)"testpublickey", strlen("testpublickey"));
    mock().expectOneCall("get_item_failure_handler")
        .withIntParameter("connection_id", active_connection_id)
        .withPointerParameter("userdata", (void *) userdata);
    receive_incoming_data_frame(active_connection, "{\"id\":\"1\",\"jsonrpc\":\"2.0\",\"result\":{\"key_name\":\"DLMS\", \"key_data\":\"\"}}");

    mock().checkExpectations();
    delete key_data_pointer;
    delete value_pointer;
}

TEST(pt_crypto_api_2, test_pt_crypto_get_public_key_missing_handlers)
{
    const char *userdata = "dummy_userdata";

    pt_status_t status = pt_crypto_get_public_key(active_connection_id,
                                                  "DLMS",
                                                  NULL,
                                                  get_item_failure_handler,
                                                  (void *) userdata);
    CHECK_EQUAL(PT_STATUS_ALLOCATION_FAIL, status);

    status = pt_crypto_get_public_key(active_connection_id,
                                      "DLMS",
                                      NULL,
                                      NULL,
                                      (void *) userdata);
    CHECK_EQUAL(PT_STATUS_ALLOCATION_FAIL, status);


    status = pt_crypto_get_public_key(active_connection_id,
                                      "DLMS",
                                      get_item_success_handler,
                                      NULL,
                                      (void *) userdata);
    CHECK_EQUAL(PT_STATUS_ALLOCATION_FAIL, status);
}

TEST(pt_crypto_api_2, test_pt_crypto_get_public_key_empty_name)
{
    const char *userdata = "dummy_userdata";

    pt_status_t status = pt_crypto_get_public_key(active_connection_id,
                                                  NULL,
                                                  get_item_success_handler,
                                                  get_item_failure_handler,
                                                  (void *) userdata);
    CHECK_EQUAL(PT_STATUS_INVALID_PARAMETERS, status);
}

TEST(pt_crypto_api_2, test_pt_crypto_generate_random)
{
    const char *userdata = "dummy_userdata";

    pt_client_t *client = active_connection->client;
    client->userdata = (void *) userdata;

    expect_msg_api_message();
    ValuePointer *value_pointer = expect_outgoing_data_frame(
                                                             "{\"id\":\"1\",\"jsonrpc\":\"2.0\",\"method\":\"crypto_generate_random\",\"params\":{"
                                                             "\"size\":10}}");
    pt_status_t status = pt_crypto_generate_random(active_connection_id,
                                                   10,
                                                   get_item_success_handler,
                                                   crypto_failure_handler,
                                                   (void *) userdata);
    CHECK_EQUAL(PT_STATUS_SUCCESS, status);
    process_event_loop_send_message(true /* connection found */);
    receive_incoming_data_frame_expectations();

    // random buffer, passed to callback function: testrandom
    // base64 encoded, in json rpc api: dGVzdHJhbmRvbQ==
    ValuePointer *random_data_pointer = new ValuePointer((const uint8_t *)"testrandom", strlen("testrandom"));
    mock().expectOneCall("get_item_success_handler")
        .withIntParameter("connection_id", active_connection_id)
        .withParameterOfType("ValuePointer", "data", (const void *) random_data_pointer)
        .withPointerParameter("userdata", (void *) userdata);
    receive_incoming_data_frame(active_connection, "{\"id\":\"1\",\"jsonrpc\":\"2.0\",\"result\":{\"data\":\"dGVzdHJhbmRvbQ==\"}}");

    mock().checkExpectations();
    delete random_data_pointer;
    delete value_pointer;
}

TEST(pt_crypto_api_2, test_pt_crypto_generate_random_failure)
{
    const char *userdata = "dummy_userdata";

    pt_client_t *client = active_connection->client;
    client->userdata = (void *) userdata;

    expect_msg_api_message();
    ValuePointer *value_pointer = expect_outgoing_data_frame(
                                                             "{\"id\":\"1\",\"jsonrpc\":\"2.0\",\"method\":\"crypto_generate_random\",\"params\":{"
                                                             "\"size\":10}}");
    pt_status_t status = pt_crypto_generate_random(active_connection_id,
                                                   10,
                                                   get_item_success_handler,
                                                   crypto_failure_handler,
                                                   (void *) userdata);
    CHECK_EQUAL(PT_STATUS_SUCCESS, status);
    process_event_loop_send_message(true /* connection found */);
    receive_incoming_data_frame_expectations();

    mock().expectOneCall("crypto_failure_handler")
        .withIntParameter("connection_id", active_connection_id)
        .withIntParameter("errorcode", 1)
        .withPointerParameter("userdata", (void *) userdata);
    receive_incoming_data_frame(active_connection,
                                "{\"id\":\"1\",\"jsonrpc\":\"2.0\",\"error\":{\"message\":\"Internal Error\","
                                "\"data\":\"Could not send crypto api event.\",\"code\":1}}");

    mock().checkExpectations();
    delete value_pointer;
}

TEST(pt_crypto_api_2, test_pt_crypto_generate_random_invalid_params)
{
    const char *userdata = "dummy_userdata";

    pt_client_t *client = active_connection->client;
    client->userdata = (void *) userdata;

    pt_status_t status = pt_crypto_generate_random(active_connection_id,
                                                   0,
                                                   get_item_success_handler,
                                                   crypto_failure_handler,
                                                   (void *) userdata);
    CHECK_EQUAL(PT_STATUS_INVALID_PARAMETERS, status);
}

TEST(pt_crypto_api_2, test_pt_crypto_generate_random_missing_handlers)
{
    const char *userdata = "dummy_userdata";

    pt_client_t *client = active_connection->client;
    client->userdata = (void *) userdata;

    pt_status_t status = pt_crypto_generate_random(active_connection_id,
                                       10,
                                       NULL,
                                       NULL,
                                       (void *) userdata);
    CHECK_EQUAL(PT_STATUS_ALLOCATION_FAIL, status);

    status = pt_crypto_generate_random(active_connection_id,
                                       10,
                                       NULL,
                                       crypto_failure_handler,
                                       (void *) userdata);
    CHECK_EQUAL(PT_STATUS_ALLOCATION_FAIL, status);

    status = pt_crypto_generate_random(active_connection_id,
                                       10,
                                       get_item_success_handler,
                                       NULL,
                                       (void *) userdata);
    CHECK_EQUAL(PT_STATUS_ALLOCATION_FAIL, status);
}

TEST(pt_crypto_api_2, test_pt_crypto_asymmetric_sign)
{
    const char *userdata = "dummy_userdata";

    pt_client_t *client = active_connection->client;
    client->userdata = (void *) userdata;

    expect_msg_api_message();
    ValuePointer *value_pointer = expect_outgoing_data_frame(
                                                             "{\"id\":\"1\",\"jsonrpc\":\"2.0\",\"method\":\"crypto_asymmetric_sign\",\"params\":{"
                                                             "\"hash_digest\":\"c29tZWhhc2g=\",\"private_key_name\":\"privatekey\"}}");
    pt_status_t status = pt_crypto_asymmetric_sign(active_connection_id,
                                                   "privatekey",
                                                   "somehash",
                                                   strlen("somehash"),
                                                   get_item_success_handler,
                                                   crypto_failure_handler,
                                                   (void *) userdata);
    CHECK_EQUAL(PT_STATUS_SUCCESS, status);
    process_event_loop_send_message(true /* connection found */);
    receive_incoming_data_frame_expectations();

    ValuePointer *data_pointer = new ValuePointer((const uint8_t *)"testdata", strlen("testdata"));
    mock().expectOneCall("get_item_success_handler")
        .withIntParameter("connection_id", active_connection_id)
        .withParameterOfType("ValuePointer", "data", (const void *) data_pointer)
        .withPointerParameter("userdata", (void *) userdata);
    receive_incoming_data_frame(active_connection, "{\"id\":\"1\",\"jsonrpc\":\"2.0\",\"result\":{\"signature_data\":\"dGVzdGRhdGE=\"}}");

    mock().checkExpectations();
    delete data_pointer;
    delete value_pointer;
}

TEST(pt_crypto_api_2, test_pt_crypto_asymmetric_sign_invalid_params)
{
    const char *userdata = "dummy_userdata";

    pt_client_t *client = active_connection->client;
    client->userdata = (void *) userdata;

    pt_status_t status = pt_crypto_asymmetric_sign(active_connection_id,
                                                   NULL,
                                                   "somehash",
                                                   strlen("somehash"),
                                                   get_item_success_handler,
                                                   crypto_failure_handler,
                                                   (void *) userdata);
    CHECK_EQUAL(PT_STATUS_INVALID_PARAMETERS, status);

    status = pt_crypto_asymmetric_sign(active_connection_id,
                                       "privatekey",
                                       NULL,
                                       strlen("somehash"),
                                       get_item_success_handler,
                                       crypto_failure_handler,
                                       (void *) userdata);
    CHECK_EQUAL(PT_STATUS_INVALID_PARAMETERS, status);

    status = pt_crypto_asymmetric_sign(active_connection_id,
                                       "privatekey",
                                       "somehash",
                                       0,
                                       get_item_success_handler,
                                       crypto_failure_handler,
                                       (void *) userdata);
    CHECK_EQUAL(PT_STATUS_INVALID_PARAMETERS, status);
}
TEST(pt_crypto_api_2, test_pt_crypto_asymmetric_sign_missing_handlers)
{
    const char *userdata = "dummy_userdata";

    pt_client_t *client = active_connection->client;
    client->userdata = (void *) userdata;

    pt_status_t status = pt_crypto_asymmetric_sign(active_connection_id,
                                       "privatekey",
                                       "somehash",
                                       strlen("somehash"),
                                       NULL,
                                       crypto_failure_handler,
                                       (void *) userdata);
    CHECK_EQUAL(PT_STATUS_ALLOCATION_FAIL, status);

    status = pt_crypto_asymmetric_sign(active_connection_id,
                                       "privatekey",
                                       "somehash",
                                       strlen("somehash"),
                                       get_item_success_handler,
                                       NULL,
                                       (void *) userdata);
    CHECK_EQUAL(PT_STATUS_ALLOCATION_FAIL, status);

    status = pt_crypto_asymmetric_sign(active_connection_id,
                                       "privatekey",
                                       "somehash",
                                       strlen("somehash"),
                                       NULL,
                                       NULL,
                                       (void *) userdata);
    CHECK_EQUAL(PT_STATUS_ALLOCATION_FAIL, status);
}

TEST(pt_crypto_api_2, test_pt_crypto_asymmetric_verify)
{
    const char *userdata = "dummy_userdata";

    pt_client_t *client = active_connection->client;
    client->userdata = (void *) userdata;

    expect_msg_api_message();
    ValuePointer *value_pointer = expect_outgoing_data_frame(
                                                             "{\"id\":\"1\",\"jsonrpc\":\"2.0\",\"method\":\"crypto_asymmetric_verify\",\"params\":{"
                                                             "\"hash_digest\":\"c29tZWhhc2g=\",\"public_key_name\":\"publickey\",\"signature\":\"dGVzdGRhdGE=\"}}");
    pt_status_t status = pt_crypto_asymmetric_verify(active_connection_id,
                                                     "publickey",
                                                     "somehash",
                                                     strlen("somehash"),
                                                     "testdata",
                                                     strlen("testdata"),
                                                     get_item_success_handler,
                                                     crypto_failure_handler,
                                                     (void *) userdata);
    CHECK_EQUAL(PT_STATUS_SUCCESS, status);
    process_event_loop_send_message(true /* connection found */);
    receive_incoming_data_frame_expectations();

    ValuePointer *data_pointer = new ValuePointer((const uint8_t *)NULL, 0);
    mock().expectOneCall("get_item_success_handler")
        .withIntParameter("connection_id", active_connection_id)
        .withParameterOfType("ValuePointer", "data", (const void *) data_pointer)
        .withPointerParameter("userdata", (void *) userdata);
    receive_incoming_data_frame(active_connection, "{\"id\":\"1\",\"jsonrpc\":\"2.0\",\"result\":\"ok\"}");

    mock().checkExpectations();
    delete data_pointer;
    delete value_pointer;
}

TEST(pt_crypto_api_2, test_pt_crypto_asymmetric_verify_invalid_params)
{
    const char *userdata = "dummy_userdata";

    pt_client_t *client = active_connection->client;
    client->userdata = (void *) userdata;

    pt_status_t status = pt_crypto_asymmetric_verify(active_connection_id,
                                                     NULL,
                                                     "somehash",
                                                     strlen("somehash"),
                                                     "testdata",
                                                     strlen("testdata"),
                                                     get_item_success_handler,
                                                     crypto_failure_handler,
                                                     (void *) userdata);
    CHECK_EQUAL(PT_STATUS_INVALID_PARAMETERS, status);

    status = pt_crypto_asymmetric_verify(active_connection_id,
                                         "publickey",
                                         NULL,
                                         strlen("somehash"),
                                         "testdata",
                                         strlen("testdata"),
                                         get_item_success_handler,
                                         crypto_failure_handler,
                                         (void *) userdata);
    CHECK_EQUAL(PT_STATUS_INVALID_PARAMETERS, status);

    status = pt_crypto_asymmetric_verify(active_connection_id,
                                         "publickey",
                                         "somehash",
                                         0,
                                         "testdata",
                                         strlen("testdata"),
                                         get_item_success_handler,
                                         crypto_failure_handler,
                                         (void *) userdata);
    CHECK_EQUAL(PT_STATUS_INVALID_PARAMETERS, status);

    status = pt_crypto_asymmetric_verify(active_connection_id,
                                         "publickey",
                                         "somehash",
                                         strlen("somehash"),
                                         NULL,
                                         strlen("testdata"),
                                         get_item_success_handler,
                                         crypto_failure_handler,
                                         (void *) userdata);
    CHECK_EQUAL(PT_STATUS_INVALID_PARAMETERS, status);

    status = pt_crypto_asymmetric_verify(active_connection_id,
                                         "publickey",
                                         "somehash",
                                         strlen("somehash"),
                                         "testdata",
                                         0,
                                         get_item_success_handler,
                                         crypto_failure_handler,
                                         (void *) userdata);
    CHECK_EQUAL(PT_STATUS_INVALID_PARAMETERS, status);
}

TEST(pt_crypto_api_2, test_pt_crypto_asymmetric_verify_missing_handlers)
{
    const char *userdata = "dummy_userdata";

    pt_client_t *client = active_connection->client;
    client->userdata = (void *) userdata;

    pt_status_t status = pt_crypto_asymmetric_verify(active_connection_id,
                                         "publickey",
                                         "somehash",
                                         strlen("somehash"),
                                         "testdata",
                                         strlen("testdata"),
                                         NULL,
                                         crypto_failure_handler,
                                         (void *) userdata);
    CHECK_EQUAL(PT_STATUS_ALLOCATION_FAIL, status);

    status = pt_crypto_asymmetric_verify(active_connection_id,
                                         "publickey",
                                         "somehash",
                                         strlen("somehash"),
                                         "testdata",
                                         strlen("testdata"),
                                         get_item_success_handler,
                                         NULL,
                                         (void *) userdata);
    CHECK_EQUAL(PT_STATUS_ALLOCATION_FAIL, status);

    status = pt_crypto_asymmetric_verify(active_connection_id,
                                         "publickey",
                                         "somehash",
                                         strlen("somehash"),
                                         "testdata",
                                         strlen("testdata"),
                                         NULL,
                                         NULL,
                                         (void *) userdata);
    CHECK_EQUAL(PT_STATUS_ALLOCATION_FAIL, status);
}

#ifndef PARSEC_TPM_SE_SUPPORT
TEST(pt_crypto_api_2, test_pt_crypto_ecdh_key_agreement)
{
    const char *userdata = "dummy_userdata";

    pt_client_t *client = active_connection->client;
    client->userdata = (void *) userdata;

    expect_msg_api_message();
    ValuePointer *value_pointer = expect_outgoing_data_frame(
                                                             "{\"id\":\"1\",\"jsonrpc\":\"2.0\",\"method\":\"crypto_ecdh_key_agreement\",\"params\":{"
                                                             "\"peer_public_key\":\"dGVzdGRhdGE=\",\"private_key_name\":\"privatekey\"}}");
    pt_status_t status = pt_crypto_ecdh_key_agreement(active_connection_id,
                                                      "privatekey",
                                                      "testdata",
                                                      strlen("testdata"),
                                                      get_item_success_handler,
                                                      crypto_failure_handler,
                                                      (void *) userdata);
    CHECK_EQUAL(PT_STATUS_SUCCESS, status);
    process_event_loop_send_message(true /* connection found */);
    receive_incoming_data_frame_expectations();

    ValuePointer *data_pointer = new ValuePointer((const uint8_t *)"secret", strlen("secret"));
    mock().expectOneCall("get_item_success_handler")
        .withIntParameter("connection_id", active_connection_id)
        .withParameterOfType("ValuePointer", "data", (const void *) data_pointer)
        .withPointerParameter("userdata", (void *) userdata);
    receive_incoming_data_frame(active_connection, "{\"id\":\"1\",\"jsonrpc\":\"2.0\",\"result\":{\"shared_secret\":\"c2VjcmV0\"}}");

    mock().checkExpectations();
    delete data_pointer;
    delete value_pointer;
}

TEST(pt_crypto_api_2, test_pt_crypto_ecdh_key_agreement_invalid_params)
{
    const char *userdata = "dummy_userdata";

    pt_client_t *client = active_connection->client;
    client->userdata = (void *) userdata;

    pt_status_t status = pt_crypto_ecdh_key_agreement(active_connection_id,
                                                      NULL,
                                                      "testdata",
                                                      strlen("testdata"),
                                                      get_item_success_handler,
                                                      crypto_failure_handler,
                                                      (void *) userdata);
    CHECK_EQUAL(PT_STATUS_INVALID_PARAMETERS, status);

    status = pt_crypto_ecdh_key_agreement(active_connection_id,
                                          "privatekey",
                                          NULL,
                                          strlen("testdata"),
                                          get_item_success_handler,
                                          crypto_failure_handler,
                                          (void *) userdata);
    CHECK_EQUAL(PT_STATUS_INVALID_PARAMETERS, status);

    status = pt_crypto_ecdh_key_agreement(active_connection_id,
                                          "privatekey",
                                          "testdata",
                                          0,
                                          get_item_success_handler,
                                          crypto_failure_handler,
                                          (void *) userdata);
    CHECK_EQUAL(PT_STATUS_INVALID_PARAMETERS, status);
}

TEST(pt_crypto_api_2, test_pt_crypto_ecdh_key_agreement_missing_handlers)
{
    const char *userdata = "dummy_userdata";

    pt_client_t *client = active_connection->client;
    client->userdata = (void *) userdata;

    pt_status_t status = pt_crypto_ecdh_key_agreement(active_connection_id,
                                          "privatekey",
                                          "testdata",
                                          strlen("testdata"),
                                          NULL,
                                          crypto_failure_handler,
                                          (void *) userdata);
    CHECK_EQUAL(PT_STATUS_ALLOCATION_FAIL, status);

    status = pt_crypto_ecdh_key_agreement(active_connection_id,
                                          "privatekey",
                                          "testdata",
                                          strlen("testdata"),
                                          get_item_success_handler,
                                          NULL,
                                          (void *) userdata);
    CHECK_EQUAL(PT_STATUS_ALLOCATION_FAIL, status);

    status = pt_crypto_ecdh_key_agreement(active_connection_id,
                                          "privatekey",
                                          "testdata",
                                          strlen("testdata"),
                                          NULL,
                                          NULL,
                                          (void *) userdata);
    CHECK_EQUAL(PT_STATUS_ALLOCATION_FAIL, status);
}
#endif // PARSEC_TPM_SE_SUPPORT