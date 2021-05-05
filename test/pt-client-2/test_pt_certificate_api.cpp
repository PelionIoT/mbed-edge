#include <stdint.h>

#include "CppUTest/TestHarness.h"
#include "CppUTestExt/MockSupport.h"

#include "test-lib/msg_api_mocks.h"
#include "test-lib/mutex_helper.h"
extern "C" {
#include "common/apr_base64.h"
#include "common/edge_mutex.h"
#include "pt-client-2/pt_certificate_api.h"
#include "pt-client-2/pt_certificate_api_internal.h"
#include "libwebsocket-mock/lws_mock.h"
#include "pt-client-2/pt_api_internal.h"
#include "pt-client-2/pt_client_api.h"
#include "pt-client-2/pt_client_helper.h"
#include "edge-rpc/rpc_timeout_api.h"
}
#include "pt-client-2/client_send_receive_helper.h"

TEST_GROUP(pt_certificate_api_2){
    void setup() {
        CHECK_EQUAL(0, mock_msg_api_messages_in_queue());
        reset_rpc_id_counter();
        rpc_set_generate_msg_id(test_msg_generate_id);

        mock_msg_api_wipeout_messages();
        active_connection_id = create_client_connection();
        mock().crashOnFailure();
    }

    void teardown()
    {
        CHECK_EQUAL(0, mock_msg_api_messages_in_queue());
        free_client_and_connection(active_connection_id);
        active_connection_id = PT_API_CONNECTION_ID_INVALID;
    }
};

TEST_GROUP(pt_certificate_api_2_no_connection){
    void setup() {
        CHECK_EQUAL(0, mock_msg_api_messages_in_queue());
        reset_rpc_id_counter();
        rpc_set_generate_msg_id(test_msg_generate_id);

        mock_msg_api_wipeout_messages();
        mock().crashOnFailure();
    }

    void teardown()
    {
        CHECK_EQUAL(0, mock_msg_api_messages_in_queue());
        active_connection_id = PT_API_CONNECTION_ID_INVALID;
    }
};

class CertChainComparator: public MockNamedValueComparator {
public:
    virtual bool isEqual(const void* object1, const void* object2)
    {
        return (valueToString(object1) == valueToString(object2));
    }

    SimpleString certToString(const struct cert_context_s *cert)
    {
        if (cert == NULL) {
            return StringFrom("(null)");
        }
        SimpleString s;
        s += StringFrom("<");
        s += StringFromBinaryWithSizeOrNull(cert->cert, cert->cert_length);
        s += StringFrom(" | next = ");
        s += certToString(cert->next);
        s += StringFrom(">");
        return s;
    }

    SimpleString valueToString(const void *object)
    {
        SimpleString s;
        if (object == NULL) {
            return StringFrom("(null)");
        }
        struct cert_chain_context_s *cc = (struct cert_chain_context_s *) object;
        s += StringFrom("size = ") + StringFrom(cc->chain_length);
        if (cc->chain_length > 0) {
            s += StringFrom(" | certificates: [");
            s += certToString(cc->certs);
            s += StringFrom("]");
        }
        return s;
    }
};

static pt_certificate_list_t *create_cert_list_with_items()
{
    pt_certificate_list_t *list = pt_certificate_list_create();
    CHECK_EQUAL(PT_STATUS_SUCCESS, pt_certificate_list_add(list, "DLMS"));
    CHECK_EQUAL(PT_STATUS_SUCCESS, pt_certificate_list_add(list, "WiSun"));
    CHECK_EQUAL(PT_STATUS_INVALID_PARAMETERS, pt_certificate_list_add(NULL, "WiSun"));
    CHECK_EQUAL(PT_STATUS_INVALID_PARAMETERS, pt_certificate_list_add(list, NULL));
    return list;
}

TEST(pt_certificate_api_2, test_pt_certificate_list)
{
    pt_certificate_list_t *list = create_cert_list_with_items();
    pt_certificate_list_destroy(list);

    mock().checkExpectations();
}

static void test_certificates_set_success_handler(const connection_id_t connection_id, void *userdata)
{
    mock().actualCall("test_certificates_set_success_handler")
            .withIntParameter("connection_id", connection_id)
            .withPointerParameter("userdata", userdata);
}

static void test_certificates_set_failure_handler(const connection_id_t connection_id, void *userdata)
{
    mock().actualCall("test_certificates_set_failure_handler")
            .withIntParameter("connection_id", connection_id)
            .withPointerParameter("userdata", userdata);
}

TEST(pt_certificate_api_2, test_pt_certificate_renewal_list_set_invalid_params)
{
    const char *userdata = "dummy_userdata";

    pt_status_t status = pt_certificate_renewal_list_set(active_connection_id,
                                                         NULL,
                                                         test_certificates_set_success_handler,
                                                         test_certificates_set_failure_handler,
                                                         (void *) userdata);
    CHECK_EQUAL(PT_STATUS_INVALID_PARAMETERS, status);
}

TEST(pt_certificate_api_2, test_pt_certificate_renewal_list_set_success)
{
    const char *userdata = "dummy_userdata";

    pt_client_t *client = active_connection->client;
    client->userdata = (void *) userdata;

    pt_certificate_list_t *list = create_cert_list_with_items();
    expect_msg_api_message();
    ValuePointer *value_pointer = expect_outgoing_data_frame(
            "{\"id\":\"1\",\"jsonrpc\":\"2.0\",\"method\":\"certificate_renewal_list_set\",\"params\":{"
            "\"certificates\":[\"DLMS\",\"WiSun\"]}}");
    pt_status_t status = pt_certificate_renewal_list_set(active_connection_id,
                                                         list,
                                                         test_certificates_set_success_handler,
                                                         test_certificates_set_failure_handler,
                                                         (void *) userdata);
    CHECK_EQUAL(PT_STATUS_SUCCESS, status);
    process_event_loop_send_message(true /* connection found */);
    receive_incoming_data_frame_expectations();
    mock().expectOneCall("test_certificates_set_success_handler")
            .withIntParameter("connection_id", active_connection_id)
            .withPointerParameter("userdata", (void *) userdata);
    receive_incoming_data_frame(active_connection, "{\"id\":\"1\",\"jsonrpc\":\"2.0\",\"result\":\"ok\"}");

    pt_certificate_list_destroy(list);

    mock().checkExpectations();
    delete value_pointer;
}

TEST(pt_certificate_api_2, test_pt_certificate_renewal_list_set_failure_response)
{
    const char *userdata = "dummy_userdata";

    pt_client_t *client = active_connection->client;
    client->userdata = (void *) userdata;

    pt_certificate_list_t *list = create_cert_list_with_items();
    expect_msg_api_message();
    ValuePointer *value_pointer = expect_outgoing_data_frame(
            "{\"id\":\"1\",\"jsonrpc\":\"2.0\",\"method\":\"certificate_renewal_list_set\",\"params\":{"
            "\"certificates\":[\"DLMS\",\"WiSun\"]}}");
    pt_status_t status = pt_certificate_renewal_list_set(active_connection_id,
                                                         list,
                                                         test_certificates_set_success_handler,
                                                         test_certificates_set_failure_handler,
                                                         (void *) userdata);
    CHECK_EQUAL(PT_STATUS_SUCCESS, status);
    process_event_loop_send_message(true /* connection found */);
    receive_incoming_data_frame_expectations();
    mock().expectOneCall("test_certificates_set_failure_handler")
            .withIntParameter("connection_id", active_connection_id)
            .withPointerParameter("userdata", (void *) userdata);
    receive_incoming_data_frame(active_connection,
                                "{\"id\":\"1\",\"jsonrpc\":\"2.0\",\"error\":{\"message\":\"Invalid "
                                "Params\",\"data\":\"Certificate renewal failed. No request id was given.\"}}");

    pt_certificate_list_destroy(list);

    mock().checkExpectations();
    delete value_pointer;
}

static void test_certificate_renew_success_handler(const connection_id_t connection_id, void *userdata)
{
    mock().actualCall("test_certificate_renew_success_handler")
            .withIntParameter("connection_id", connection_id)
            .withPointerParameter("userdata", userdata);
}

static void test_certificate_renew_failure_handler(const connection_id_t connection_id, void *userdata)
{
    mock().actualCall("test_certificate_renew_failure_handler")
            .withIntParameter("connection_id", connection_id)
            .withPointerParameter("userdata", userdata);
}

TEST(pt_certificate_api_2, test_pt_certificate_renew_success)
{
    const char *userdata = "dummy_userdata";

    pt_client_t *client = active_connection->client;
    client->userdata = (void *) userdata;

    pt_certificate_list_t *list = create_cert_list_with_items();
    expect_msg_api_message();
    ValuePointer *value_pointer = expect_outgoing_data_frame(
            "{\"id\":\"1\",\"jsonrpc\":\"2.0\",\"method\":\"renew_certificate\",\"params\":{"
            "\"certificate\":\"DLMS\"}}");
    pt_status_t status = pt_certificate_renew(active_connection_id,
                                              "DLMS",
                                              test_certificate_renew_success_handler,
                                              test_certificate_renew_failure_handler,
                                              (void *) userdata);
    CHECK_EQUAL(PT_STATUS_SUCCESS, status);
    process_event_loop_send_message(true /* connection found */);
    receive_incoming_data_frame_expectations();
    mock().expectOneCall("test_certificate_renew_success_handler")
            .withIntParameter("connection_id", active_connection_id)
            .withPointerParameter("userdata", (void *) userdata);
    receive_incoming_data_frame(active_connection, "{\"id\":\"1\",\"jsonrpc\":\"2.0\",\"result\":\"ok\"}");

    pt_certificate_list_destroy(list);

    mock().checkExpectations();
    delete value_pointer;
}

TEST(pt_certificate_api_2, test_pt_certificate_renew_failure)
{
    const char *userdata = "dummy_userdata";

    pt_client_t *client = active_connection->client;
    client->userdata = (void *) userdata;

    expect_msg_api_message();
    ValuePointer *value_pointer = expect_outgoing_data_frame(
            "{\"id\":\"1\",\"jsonrpc\":\"2.0\",\"method\":\"renew_certificate\",\"params\":{"
            "\"certificate\":\"DLMS\"}}");
    pt_status_t status = pt_certificate_renew(active_connection_id,
                                              "DLMS",
                                              test_certificate_renew_success_handler,
                                              test_certificate_renew_failure_handler,
                                              (void *) userdata);
    CHECK_EQUAL(PT_STATUS_SUCCESS, status);
    process_event_loop_send_message(true /* connection found */);
    receive_incoming_data_frame_expectations();
    mock().expectOneCall("test_certificate_renew_failure_handler")
            .withIntParameter("connection_id", active_connection_id)
            .withPointerParameter("userdata", (void *) userdata);
    receive_incoming_data_frame(active_connection,
                                "{\"id\":\"1\",\"jsonrpc\":\"2.0\",\"error\":{\"message\":\"Invalid "
                                "Params\",\"data\":\"Certificate renewal failed. No request id was given.\"}}");

    mock().checkExpectations();
    delete value_pointer;
}

const unsigned int test_csr_len = 277;
const char* test_csr_base64 = "MIIBETCBuAIBADBWMQswCQYDVQQGEwJGSTENMAsGA1UECAwET3VsdTENMAsGA1UEBwwET3VsdTEMMAoGA1UECgwDQVJNMQwwCgYDVQQLDANJU0cxDTALBgNVBAMMBERMTVMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQgLP5LgTcshkX83SxExnHHn1vWx2XKUBnwhioRWqoTLdQmRVkdyUwYC4W0jaB96A+5KGC1SFXOL+nZwPHMvE2ooAAwCgYIKoZIzj0EAwIDSAAwRQIgE0EJxRGq5YRAvw7MeIpNAd+E/TSaypShxtI2IIH5UEMCIQDNZvbzZJnLROp6CzM/Ay7RBrfVggutzdhUK70cdziagw==";

static void test_device_cert_renew_success_handler(const connection_id_t connection_id,
                                     const char *device_id,
                                     const char *name,
                                     int32_t status,
                                     struct cert_chain_context_s *cert_chain,
                                     void *userdata)
{
    mock().setData("cert_chain", cert_chain);
    mock().actualCall("test_device_cert_renew_success_handler")
        .withIntParameter("connection_id", connection_id)
        .withParameterOfType("CertChain", "cert_chain", cert_chain)
        .withPointerParameter("userdata", userdata);
}

static void test_device_cert_renew_failure_handler(const connection_id_t connection_id,
                                     const char *device_id,
                                     const char *name,
                                     int32_t status,
                                     struct cert_chain_context_s *cert_chain,
                                     void *userdata)
{
    mock().setData("cert_chain", cert_chain);
    mock().actualCall("test_device_cert_renew_failure_handler")
        .withIntParameter("connection_id", connection_id)
        .withParameterOfType("CertChain", "cert_chain", cert_chain)
        .withPointerParameter("userdata", userdata);
}

#define request_tlv_len 18
const unsigned char request_tlv[request_tlv_len] = {0x00, 0x01, 0x00, 0x06, 'L', 'W', 'M', '2', 'M', 0x00, 0x80, 0x0F, 0x00, 0x04, 't', 'e', 's', 't'};

TEST(pt_certificate_api_2, test_pt_device_cert_renew_success_single_cert)
{
    const char *userdata = "dummy_userdata";

    mock().setData("cert_chain", (void*)NULL);

    size_t csr_len = apr_base64_decode_len(test_csr_base64);
    char *csr_binary = (char *) calloc(1, csr_len);
    apr_base64_decode_binary((unsigned char *) csr_binary, test_csr_base64);

    pt_client_t *client = active_connection->client;
    client->userdata = (void *) userdata;

    mock().expectNCalls(6, "edge_mutex_lock").withPointerParameter("mutex", &api_mutex).andReturnValue(0);
    mock().expectNCalls(6, "edge_mutex_unlock").withPointerParameter("mutex", &api_mutex).andReturnValue(0);
    pt_device_create_with_feature_flags(active_connection->id, "somedevice", 3600, NONE, PT_DEVICE_FEATURE_CERTIFICATE_RENEWAL, NULL);

    expect_msg_api_message();
    ValuePointer *value_pointer = expect_outgoing_data_frame(
            "{\"id\":\"1\",\"jsonrpc\":\"2.0\",\"method\":\"est_request_enrollment\",\"params\":{"
            "\"certificate_name\":\"DLMS\",\"csr\":\"MIIBETCBuAIBADBWMQswCQYDVQQGEwJGSTENMAsGA1UECAwET3VsdTENMAsGA1UEBwwET3VsdTEMMAoGA1UECgwDQVJNMQwwCgYDVQQLDANJU0cxDTALBgNVBAMMBERMTVMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQgLP5LgTcshkX83SxExnHHn1vWx2XKUBnwhioRWqoTLdQmRVkdyUwYC4W0jaB96A+5KGC1SFXOL+nZwPHMvE2ooAAwCgYIKoZIzj0EAwIDSAAwRQIgE0EJxRGq5YRAvw7MeIpNAd+E/TSaypShxtI2IIH5UEMCIQDNZvbzZJnLROp6CzM/Ay7RBrfVggutzdhUK70cdziagw==\"}}");
    mh_expect_mutexing(&api_mutex);
    pt_status_t status = pt_device_certificate_renew(active_connection_id,
                                                     "somedevice",
                                                     "DLMS",
                                                     csr_binary,
                                                     csr_len,
                                                     test_device_cert_renew_success_handler,
                                                     test_device_cert_renew_failure_handler,
                                                     (void *) userdata);
    CHECK_EQUAL(PT_STATUS_SUCCESS, status);
    process_event_loop_send_message(true /* connection found */);
    receive_incoming_data_frame_expectations();

    struct cert_chain_context_s expected_cc = {0};
    struct cert_context_s cert1 = {0};
    expected_cc.chain_length = 1;
    expected_cc.certs = &cert1;
    cert1.cert = (uint8_t *) "testcertificate";
    cert1.cert_length = strlen("testcertificate");

    CertChainComparator comparator;
    mock().installComparator("CertChain", comparator);
    mock().expectOneCall("test_device_cert_renew_success_handler")
        .withIntParameter("connection_id", active_connection_id)
        .withParameterOfType("CertChain", "cert_chain", (const void *) &expected_cc)
        .withPointerParameter("userdata", (void *) userdata);
    receive_incoming_data_frame(active_connection, "{\"id\":\"1\",\"jsonrpc\":\"2.0\",\"result\":{\"certificate_data\":[\"dGVzdGNlcnRpZmljYXRl\"]}}");

    mock().checkExpectations();
    delete value_pointer;

    struct cert_chain_context_s *ctx = (struct cert_chain_context_s *) mock().getData("cert_chain").getObjectPointer();
    pt_free_certificate_chain_context(ctx);

    free(csr_binary);
}

TEST(pt_certificate_api_2, test_pt_device_cert_renew_success_multi_cert)
{
    const char *userdata = "dummy_userdata";

    mock().setData("cert_chain", (void*)NULL);

    size_t csr_len = apr_base64_decode_len(test_csr_base64);
    char *csr_binary = (char *) calloc(1, csr_len);
    apr_base64_decode_binary((unsigned char *) csr_binary, test_csr_base64);

    pt_client_t *client = active_connection->client;
    client->userdata = (void *) userdata;

    mock().expectNCalls(6, "edge_mutex_lock").withPointerParameter("mutex", &api_mutex).andReturnValue(0);
    mock().expectNCalls(6, "edge_mutex_unlock").withPointerParameter("mutex", &api_mutex).andReturnValue(0);
    pt_device_create_with_feature_flags(active_connection->id, "somedevice", 3600, NONE, PT_DEVICE_FEATURE_CERTIFICATE_RENEWAL, NULL);

    expect_msg_api_message();
    ValuePointer *value_pointer = expect_outgoing_data_frame(
            "{\"id\":\"1\",\"jsonrpc\":\"2.0\",\"method\":\"est_request_enrollment\",\"params\":{"
            "\"certificate_name\":\"DLMS\",\"csr\":\"MIIBETCBuAIBADBWMQswCQYDVQQGEwJGSTENMAsGA1UECAwET3VsdTENMAsGA1UEBwwET3VsdTEMMAoGA1UECgwDQVJNMQwwCgYDVQQLDANJU0cxDTALBgNVBAMMBERMTVMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQgLP5LgTcshkX83SxExnHHn1vWx2XKUBnwhioRWqoTLdQmRVkdyUwYC4W0jaB96A+5KGC1SFXOL+nZwPHMvE2ooAAwCgYIKoZIzj0EAwIDSAAwRQIgE0EJxRGq5YRAvw7MeIpNAd+E/TSaypShxtI2IIH5UEMCIQDNZvbzZJnLROp6CzM/Ay7RBrfVggutzdhUK70cdziagw==\"}}");
    mh_expect_mutexing(&api_mutex);
    pt_status_t status = pt_device_certificate_renew(active_connection_id,
                                                     "somedevice",
                                                     "DLMS",
                                                     csr_binary,
                                                     csr_len,
                                                     test_device_cert_renew_success_handler,
                                                     test_device_cert_renew_failure_handler,
                                                     (void *) userdata);
    CHECK_EQUAL(PT_STATUS_SUCCESS, status);
    process_event_loop_send_message(true /* connection found */);
    receive_incoming_data_frame_expectations();

    struct cert_chain_context_s expected_cc = {0};
    struct cert_context_s cert2 = {.cert_length = strlen("secondcertificate"), .cert = (uint8_t *) "secondcertificate", .next = NULL};
    struct cert_context_s cert1 = {.cert_length = strlen("testcertificate"), .cert = (uint8_t *) "testcertificate", .next = &cert2};
    expected_cc.chain_length = 2;
    expected_cc.certs = &cert1;

    CertChainComparator comparator;
    mock().installComparator("CertChain", comparator);
    mock().expectOneCall("test_device_cert_renew_success_handler")
        .withIntParameter("connection_id", active_connection_id)
        .withParameterOfType("CertChain", "cert_chain", (const void *) &expected_cc)
        .withPointerParameter("userdata", (void *) userdata);
    receive_incoming_data_frame(active_connection, "{\"id\":\"1\",\"jsonrpc\":\"2.0\",\"result\":{\"certificate_data\":[\"dGVzdGNlcnRpZmljYXRl\", \"c2Vjb25kY2VydGlmaWNhdGU=\"]}}");

    mock().checkExpectations();
    delete value_pointer;

    struct cert_chain_context_s *ctx = (struct cert_chain_context_s *) mock().getData("cert_chain").getObjectPointer();
    pt_free_certificate_chain_context(ctx);

    free(csr_binary);
}

TEST(pt_certificate_api_2, test_pt_device_cert_renew_failure_missing_certificates)
{
    const char *userdata = "dummy_userdata";

    mock().setData("cert_chain", (void*)NULL);

    size_t csr_len = apr_base64_decode_len(test_csr_base64);
    char *csr_binary = (char *) calloc(1, csr_len);
    apr_base64_decode_binary((unsigned char *) csr_binary, test_csr_base64);

    pt_client_t *client = active_connection->client;
    client->userdata = (void *) userdata;

    mock().expectNCalls(6, "edge_mutex_lock").withPointerParameter("mutex", &api_mutex).andReturnValue(0);
    mock().expectNCalls(6, "edge_mutex_unlock").withPointerParameter("mutex", &api_mutex).andReturnValue(0);
    pt_device_create_with_feature_flags(active_connection->id, "somedevice", 3600, NONE, PT_DEVICE_FEATURE_CERTIFICATE_RENEWAL, NULL);

    expect_msg_api_message();
    ValuePointer *value_pointer = expect_outgoing_data_frame(
            "{\"id\":\"1\",\"jsonrpc\":\"2.0\",\"method\":\"est_request_enrollment\",\"params\":{"
            "\"certificate_name\":\"DLMS\",\"csr\":\"MIIBETCBuAIBADBWMQswCQYDVQQGEwJGSTENMAsGA1UECAwET3VsdTENMAsGA1UEBwwET3VsdTEMMAoGA1UECgwDQVJNMQwwCgYDVQQLDANJU0cxDTALBgNVBAMMBERMTVMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQgLP5LgTcshkX83SxExnHHn1vWx2XKUBnwhioRWqoTLdQmRVkdyUwYC4W0jaB96A+5KGC1SFXOL+nZwPHMvE2ooAAwCgYIKoZIzj0EAwIDSAAwRQIgE0EJxRGq5YRAvw7MeIpNAd+E/TSaypShxtI2IIH5UEMCIQDNZvbzZJnLROp6CzM/Ay7RBrfVggutzdhUK70cdziagw==\"}}");
    mh_expect_mutexing(&api_mutex);
    pt_status_t status = pt_device_certificate_renew(active_connection_id,
                                                     "somedevice",
                                                     "DLMS",
                                                     csr_binary,
                                                     csr_len,
                                                     test_device_cert_renew_success_handler,
                                                     test_device_cert_renew_failure_handler,
                                                     (void *) userdata);
    CHECK_EQUAL(PT_STATUS_SUCCESS, status);
    process_event_loop_send_message(true /* connection found */);
    receive_incoming_data_frame_expectations();

    CertChainComparator comparator;
    mock().installComparator("CertChain", comparator);
    mock().expectOneCall("test_device_cert_renew_failure_handler")
        .withIntParameter("connection_id", active_connection_id)
        .withParameterOfType("CertChain", "cert_chain", (const void *) NULL)
        .withPointerParameter("userdata", (void *) userdata);
    receive_incoming_data_frame(active_connection, "{\"id\":\"1\",\"jsonrpc\":\"2.0\",\"result\":{\"certificate_data\":[]}}");

    mock().checkExpectations();
    delete value_pointer;

    struct cert_chain_context_s *ctx = (struct cert_chain_context_s *) mock().getData("cert_chain").getObjectPointer();
    pt_free_certificate_chain_context(ctx);

    free(csr_binary);
}

TEST(pt_certificate_api_2, test_pt_device_cert_renew_failure_error)
{
    const char *userdata = "dummy_userdata";

    size_t csr_len = apr_base64_decode_len(test_csr_base64);
    char *csr_binary = (char *) calloc(1, csr_len);
    apr_base64_decode_binary((unsigned char *) csr_binary, test_csr_base64);

    pt_client_t *client = active_connection->client;
    client->userdata = (void *) userdata;

    mock().expectNCalls(6, "edge_mutex_lock").withPointerParameter("mutex", &api_mutex).andReturnValue(0);
    mock().expectNCalls(6, "edge_mutex_unlock").withPointerParameter("mutex", &api_mutex).andReturnValue(0);
    pt_device_create_with_feature_flags(active_connection->id, "somedevice", 3600, NONE, PT_DEVICE_FEATURE_CERTIFICATE_RENEWAL, NULL);

    expect_msg_api_message();
    ValuePointer *value_pointer = expect_outgoing_data_frame(
            "{\"id\":\"1\",\"jsonrpc\":\"2.0\",\"method\":\"est_request_enrollment\",\"params\":{"
            "\"certificate_name\":\"DLMS\",\"csr\":\"MIIBETCBuAIBADBWMQswCQYDVQQGEwJGSTENMAsGA1UECAwET3VsdTENMAsGA1UEBwwET3VsdTEMMAoGA1UECgwDQVJNMQwwCgYDVQQLDANJU0cxDTALBgNVBAMMBERMTVMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQgLP5LgTcshkX83SxExnHHn1vWx2XKUBnwhioRWqoTLdQmRVkdyUwYC4W0jaB96A+5KGC1SFXOL+nZwPHMvE2ooAAwCgYIKoZIzj0EAwIDSAAwRQIgE0EJxRGq5YRAvw7MeIpNAd+E/TSaypShxtI2IIH5UEMCIQDNZvbzZJnLROp6CzM/Ay7RBrfVggutzdhUK70cdziagw==\"}}");
    mh_expect_mutexing(&api_mutex);
    pt_status_t status = pt_device_certificate_renew(active_connection_id,
                                                     "somedevice",
                                                     "DLMS",
                                                     csr_binary,
                                                     csr_len,
                                                     test_device_cert_renew_success_handler,
                                                     test_device_cert_renew_failure_handler,
                                                     (void *) userdata);
    CHECK_EQUAL(PT_STATUS_SUCCESS, status);
    process_event_loop_send_message(true /* connection found */);
    receive_incoming_data_frame_expectations();

    CertChainComparator comparator;
    mock().installComparator("CertChain", comparator);
    mock().expectOneCall("test_device_cert_renew_failure_handler")
        .withIntParameter("connection_id", active_connection_id)
        .withParameterOfType("CertChain", "cert_chain", (const void *) NULL)
        .withPointerParameter("userdata", (void *) userdata);
    receive_incoming_data_frame(active_connection,
                                "{\"id\":\"1\",\"jsonrpc\":\"2.0\",\"error\":{\"message\":\"Invalid "
                                "Params\",\"data\":\"Certificate renewal failed. No request id was given.\"}}");

    mock().checkExpectations();
    delete value_pointer;

    free(csr_binary);
}

TEST(pt_certificate_api_2, test_pt_device_cert_renew_failure_invalid_parameters)
{
    const char *userdata = "dummy_userdata";

    size_t csr_len = apr_base64_decode_len(test_csr_base64);
    char *csr_binary = (char *) calloc(1, csr_len);
    apr_base64_decode_binary((unsigned char *) csr_binary, test_csr_base64);

    pt_client_t *client = active_connection->client;
    client->userdata = (void *) userdata;

    mock().expectNCalls(6, "edge_mutex_lock").withPointerParameter("mutex", &api_mutex).andReturnValue(0);
    mock().expectNCalls(6, "edge_mutex_unlock").withPointerParameter("mutex", &api_mutex).andReturnValue(0);
    pt_device_create_with_feature_flags(active_connection->id, "somedevice", 3600, NONE, PT_DEVICE_FEATURE_CERTIFICATE_RENEWAL, NULL);

    pt_status_t status = pt_device_certificate_renew(active_connection_id,
                                                     "somedevice",
                                                     NULL,
                                                     csr_binary,
                                                     csr_len,
                                                     test_device_cert_renew_success_handler,
                                                     test_device_cert_renew_failure_handler,
                                                     (void *) userdata);
    CHECK_EQUAL(PT_STATUS_INVALID_PARAMETERS, status);

    status = pt_device_certificate_renew(active_connection_id,
                                         "somedevice",
                                         "DLMS",
                                         NULL,
                                         csr_len,
                                         test_device_cert_renew_success_handler,
                                         test_device_cert_renew_failure_handler,
                                         (void *) userdata);
    CHECK_EQUAL(PT_STATUS_INVALID_PARAMETERS, status);

    status = pt_device_certificate_renew(active_connection_id,
                                         "somedevice",
                                         "DLMS",
                                         csr_binary,
                                         0,
                                         test_device_cert_renew_success_handler,
                                         test_device_cert_renew_failure_handler,
                                         (void *) userdata);
    CHECK_EQUAL(PT_STATUS_INVALID_PARAMETERS, status);

    status = pt_device_certificate_renew(active_connection_id,
                                         "somedevice",
                                         "DLMS",
                                         csr_binary,
                                         csr_len,
                                         NULL,
                                         test_device_cert_renew_failure_handler,
                                         (void *) userdata);
    CHECK_EQUAL(PT_STATUS_INVALID_PARAMETERS, status);

    status = pt_device_certificate_renew(active_connection_id,
                                         "somedevice",
                                         "DLMS",
                                         csr_binary,
                                         csr_len,
                                         test_device_cert_renew_success_handler,
                                         NULL,
                                         (void *) userdata);
    CHECK_EQUAL(PT_STATUS_INVALID_PARAMETERS, status);

    status = pt_device_certificate_renew(active_connection_id,
                                         "somedevice",
                                         "DLMS",
                                         csr_binary,
                                         csr_len,
                                         test_device_cert_renew_success_handler,
                                         NULL,
                                         (void *) userdata);
    CHECK_EQUAL(PT_STATUS_INVALID_PARAMETERS, status);

    free(csr_binary);
}

TEST(pt_certificate_api_2, test_pt_device_cert_renew_failure_not_supported)
{
    const char *userdata = "dummy_userdata";

    size_t csr_len = apr_base64_decode_len(test_csr_base64);
    char *csr_binary = (char *) calloc(1, csr_len);
    apr_base64_decode_binary((unsigned char *) csr_binary, test_csr_base64);

    pt_client_t *client = active_connection->client;
    client->userdata = (void *) userdata;

    mh_expect_mutexing(&api_mutex);
    mh_expect_mutexing(&api_mutex);
    pt_device_create_with_feature_flags(active_connection->id, "somedevice", 3600, NONE, PT_DEVICE_FEATURE_NONE, NULL);

    pt_status_t status = pt_device_certificate_renew(active_connection_id,
                                                     "somedevice",
                                                     "DLMS",
                                                     csr_binary,
                                                     csr_len,
                                                     test_device_cert_renew_success_handler,
                                                     test_device_cert_renew_failure_handler,
                                                     (void *) userdata);
    CHECK_EQUAL(PT_STATUS_INVALID_PARAMETERS, status);

    free(csr_binary);
}

TEST(pt_certificate_api_2, test_device_cert_renew_resource_callback_invalid_params)
{
    pt_status_t status = pt_device_certificate_renew_resource_callback(active_connection_id,
                                                                       "some_device",
                                                                       0, 0, 0, 0,
                                                                       NULL, 0, NULL);
    CHECK_EQUAL(PT_STATUS_INVALID_PARAMETERS, status);

    status = pt_device_certificate_renew_resource_callback(active_connection_id,
                                                           "some_device",
                                                           0, 0, 0, 0,
                                                           (const uint8_t *) request_tlv, 0, NULL);
    CHECK_EQUAL(PT_STATUS_INVALID_PARAMETERS, status);

    status = pt_device_certificate_renew_resource_callback(active_connection_id,
                                                           "some_device",
                                                           0, 0, 0, 0,
                                                           NULL, 5, NULL);
    CHECK_EQUAL(PT_STATUS_INVALID_PARAMETERS, status);

    mock().checkExpectations();
}

TEST(pt_certificate_api_2, test_device_cert_renew_resource_callback_request_handler_error)
{

    mock().expectNCalls(6, "edge_mutex_lock").withPointerParameter("mutex", &api_mutex).andReturnValue(0);
    mock().expectNCalls(6, "edge_mutex_unlock").withPointerParameter("mutex", &api_mutex).andReturnValue(0);
    pt_device_create_with_feature_flags(active_connection->id, "some_device", 3600, NONE, PT_DEVICE_FEATURE_CERTIFICATE_RENEWAL, NULL);

    pt_client_t *client = active_connection->client;
    pt_device_t *dev = pt_devices_find_device(client->devices, "some_device");

    mh_expect_mutexing(&api_mutex);
    mh_expect_mutexing(&api_mutex);
    mh_expect_mutexing(&api_mutex);
    mh_expect_mutexing(&api_mutex);
    mock().expectOneCall("test_device_certificate_renewal_request_handler")
        .withStringParameter("device_id", "some_device")
        .withStringParameter("name", "LWM2M")
        .withPointerParameter("userdata", NULL)
        .andReturnValue(PT_STATUS_ERROR);
    expect_msg_api_message();
    ValuePointer *value_pointer = expect_outgoing_data_frame(
                                                             "{\"id\":\"1\",\"jsonrpc\":\"2.0\",\"method\":\"write\",\"params\":{\"deviceId\":\"some_device\","
                                                             "\"objects\":[{\"objectId\":35011,\"objectInstances\":[{\"objectInstanceId\":0,\"resources\":[{"
                                                             "\"operations\":4,\"resourceId\":27002,\"type\":\"string\",\"value\":\"MTI4MA==\"},{"
                                                             "\"operations\":1,\"resourceId\":27003,\"type\":\"opaque\",\"value\":\"\"}]}]}]}}"
                                                             );
    pt_status_t status = pt_device_certificate_renew_resource_callback(active_connection_id,
                                                                       "some_device",
                                                                       0, 0, 0, 0,
                                                                       (const uint8_t *) request_tlv, request_tlv_len, NULL);
    CHECK_EQUAL(PT_STATUS_SUCCESS, status);
    process_event_loop_send_message(true /* connection found */);
    receive_incoming_data_frame_expectations();
    find_client_device_expectations();
    receive_incoming_data_frame(active_connection, "{\"id\":\"1\",\"jsonrpc\":\"2.0\",\"result\":\"ok\"}");
    mock().checkExpectations();
    CHECK(NULL == dev->csr_request_id);

    delete value_pointer;
}

TEST(pt_certificate_api_2, test_device_cert_renew_resource_callback_request_handler_success)
{

    mock().expectNCalls(6, "edge_mutex_lock").withPointerParameter("mutex", &api_mutex).andReturnValue(0);
    mock().expectNCalls(6, "edge_mutex_unlock").withPointerParameter("mutex", &api_mutex).andReturnValue(0);
    pt_device_create_with_feature_flags(active_connection->id, "some_device", 3600, NONE, PT_DEVICE_FEATURE_CERTIFICATE_RENEWAL, NULL);

    pt_client_t *client = active_connection->client;
    pt_device_t *dev = pt_devices_find_device(client->devices, "some_device");

    mock().expectOneCall("test_device_certificate_renewal_request_handler")
        .withStringParameter("device_id", "some_device")
        .withStringParameter("name", "LWM2M")
        .withPointerParameter("userdata", NULL)
        .andReturnValue(PT_STATUS_SUCCESS);
    expect_msg_api_message();
    ValuePointer *value_pointer2 = expect_outgoing_data_frame(
                                                             "{\"id\":\"1\",\"jsonrpc\":\"2.0\",\"method\":\"write\",\"params\":{\"deviceId\":\"some_device\","
                                                             "\"objects\":[{\"objectId\":35011,\"objectInstances\":[{\"objectInstanceId\":0,\"resources\":[{"
                                                             "\"operations\":4,\"resourceId\":27002,\"type\":\"string\",\"value\":\"MTUzNQ==\"},{"
                                                             "\"operations\":1,\"resourceId\":27003,\"type\":\"opaque\",\"value\":\"\"}]}]}]}}"
                                                             );
    mh_expect_mutexing(&api_mutex);
    mh_expect_mutexing(&api_mutex);
    mh_expect_mutexing(&api_mutex);
    pt_status_t status = pt_device_certificate_renew_resource_callback(active_connection_id,
                                                                       "some_device",
                                                                       0, 0, 0, 0,
                                                                       (const uint8_t *) request_tlv, request_tlv_len, NULL);
    CHECK_EQUAL(PT_STATUS_SUCCESS, status);
    process_event_loop_send_message(true); // connection found
    receive_incoming_data_frame_expectations();
    find_client_device_expectations();
    receive_incoming_data_frame(active_connection, "{\"id\":\"1\",\"jsonrpc\":\"2.0\",\"result\":\"ok\"}");

    MEMCMP_EQUAL("test", dev->csr_request_id, 4);
    free(dev->csr_request_id);

    mock().checkExpectations();
    delete value_pointer2;
}

TEST(pt_certificate_api_2, test_device_cert_renew_resource_callback_missing_cb)
{
    mh_expect_mutexing(&api_mutex);
    protocol_translator_callbacks_t pt_cbs = {0};
    active_connection->client->protocol_translator_callbacks = &pt_cbs;
    pt_status_t status = pt_device_certificate_renew_resource_callback(active_connection_id,
                                                                       "some_device",
                                                                       0, 0, 0, 0,
                                                                       (const uint8_t *) request_tlv, request_tlv_len, NULL);
    CHECK_EQUAL(PT_STATUS_NOT_FOUND, status);
    mock().checkExpectations();
}

TEST(pt_certificate_api_2_no_connection, test_device_cert_renew_resource_callback_no_connection)
{
    mh_expect_mutexing(&api_mutex);
    pt_status_t status = pt_device_certificate_renew_resource_callback(active_connection_id,
                                                                       "some_device",
                                                                       0, 0, 0, 0,
                                                                       (const uint8_t *) request_tlv, request_tlv_len, NULL);
    CHECK_EQUAL(PT_STATUS_NOT_CONNECTED, status);
    mock().checkExpectations();
}

const unsigned char expected_tlv[] = {0xC0, 0x01, 0x00, 0x04, 't', 'e', 's', 't', 0x00, 0x02, 0x00, 0x002, 0x00, 0x00};

TEST(pt_certificate_api_2, test_device_cert_renewal_finish)
{
    mock().expectNCalls(6, "edge_mutex_lock").withPointerParameter("mutex", &api_mutex).andReturnValue(0);
    mock().expectNCalls(6, "edge_mutex_unlock").withPointerParameter("mutex", &api_mutex).andReturnValue(0);
    pt_device_create_with_feature_flags(active_connection->id, "some_device", 3600, NONE, PT_DEVICE_FEATURE_CERTIFICATE_RENEWAL, NULL);
    pt_client_t *client = active_connection->client;
    mh_expect_mutexing(&api_mutex);
    mh_expect_mutexing(&api_mutex);
    pt_device_t *dev = pt_devices_find_device(client->devices, "some_device");
    dev->csr_request_id = strdup("test");
    dev->csr_request_id_len = 4;

    expect_msg_api_message();
    ValuePointer *value_pointer = expect_outgoing_data_frame(
                                                             "{\"id\":\"1\",\"jsonrpc\":\"2.0\",\"method\":\"write\",\"params\":{\"deviceId\":\"some_device\","
                                                             "\"objects\":[{\"objectId\":35011,\"objectInstances\":[{\"objectInstanceId\":0,\"resources\":[{"
                                                             "\"operations\":4,\"resourceId\":27002,\"type\":\"string\",\"value\":\"\"},{"
                                                             "\"operations\":1,\"resourceId\":27003,\"type\":\"opaque\",\"value\":\"AAIAAgAAgA8ABHRlc3Q=\"}]}]}]}}"
                                                             );
    mh_expect_mutexing(&api_mutex);
    CHECK_EQUAL(PT_STATUS_SUCCESS, pt_device_certificate_renew_request_finish(active_connection_id,
                                                                              "some_device",
                                                                              CE_STATUS_SUCCESS));
    process_event_loop_send_message(true /* connection found */);
    receive_incoming_data_frame_expectations();
    find_client_device_expectations();
    receive_incoming_data_frame(active_connection, "{\"id\":\"1\",\"jsonrpc\":\"2.0\",\"result\":\"ok\"}");

    POINTERS_EQUAL(NULL, dev->csr_request_id);

    mock().checkExpectations();
    delete value_pointer;
}

#define request_tlv_unknown_optional_type_len 28
const unsigned char request_tlv_unknown_optional_type[request_tlv_unknown_optional_type_len] = {0x00, 0x01, 0x00, 0x06, 'L', 'W', 'M', '2', 'M', 0x00, 0xC0 /* Unknown type, MSB 1 = optional */, 0x05, 0x00, 0x05, 't', 'e', 's', 't', 0x00, 0x80, 0x0F, 0x00, 0x05, 't', 'e', 's', 't', 0x00};

TEST(pt_certificate_api_2, test_device_cert_renew_resource_callback_tlv_has_unknown_optional_type_success)
{

    mock().expectNCalls(6, "edge_mutex_lock").withPointerParameter("mutex", &api_mutex).andReturnValue(0);
    mock().expectNCalls(6, "edge_mutex_unlock").withPointerParameter("mutex", &api_mutex).andReturnValue(0);
    mock().expectOneCall("test_device_certificate_renewal_request_handler")
        .withStringParameter("device_id", "some_device")
        .withStringParameter("name", "LWM2M")
        .withPointerParameter("userdata", NULL)
        .andReturnValue(PT_STATUS_SUCCESS);
    pt_device_create_with_feature_flags(active_connection->id, "some_device", 3600, NONE, PT_DEVICE_FEATURE_CERTIFICATE_RENEWAL, NULL);
    expect_msg_api_message();
    ValuePointer *value_pointer = expect_outgoing_data_frame(
                                                             "{\"id\":\"1\",\"jsonrpc\":\"2.0\",\"method\":\"write\",\"params\":{\"deviceId\":\"some_device\","
                                                             "\"objects\":[{\"objectId\":35011,\"objectInstances\":[{\"objectInstanceId\":0,\"resources\":[{"
                                                             "\"operations\":4,\"resourceId\":27002,\"type\":\"string\",\"value\":\"MTUzNQ==\"},{"
                                                             "\"operations\":1,\"resourceId\":27003,\"type\":\"opaque\",\"value\":\"\"}]}]}]}}"
                                                             );
    mh_expect_mutexing(&api_mutex);
    mh_expect_mutexing(&api_mutex);
    mh_expect_mutexing(&api_mutex);
    pt_status_t status = pt_device_certificate_renew_resource_callback(active_connection_id,
                                                                       "some_device",
                                                                       0, 0, 0, 0,
                                                                       (const uint8_t *) request_tlv_unknown_optional_type,
                                                                       request_tlv_unknown_optional_type_len, NULL);
    CHECK_EQUAL(PT_STATUS_SUCCESS, status);
    process_event_loop_send_message(true /* connection found */);
    receive_incoming_data_frame_expectations();
    find_client_device_expectations();
    receive_incoming_data_frame(active_connection, "{\"id\":\"1\",\"jsonrpc\":\"2.0\",\"result\":\"ok\"}");
    mock().checkExpectations();

    pt_client_t *client = active_connection->client;
    pt_device_t *dev = pt_devices_find_device(client->devices, "some_device");
    MEMCMP_EQUAL("test", dev->csr_request_id, 4);
    free(dev->csr_request_id);

    delete value_pointer;
}

#define request_tlv_unknown_required_type_len 28
const unsigned char request_tlv_unknown_required_type[request_tlv_unknown_required_type_len] = {0x00, 0x01, 0x00, 0x06, 'L', 'W', 'M', '2', 'M', 0x00, 0x20 /* Unknown type, MSB 0 = required */, 0x05, 0x00, 0x05, 't', 'e', 's', 't', 0x00, 0x80, 0x0F, 0x00, 0x05, 't', 'e', 's', 't', 0x00};

TEST(pt_certificate_api_2, test_device_cert_renew_resource_callback_tlv_has_unknown_required_type_fails)
{

    mock().expectNCalls(6, "edge_mutex_lock").withPointerParameter("mutex", &api_mutex).andReturnValue(0);
    mock().expectNCalls(6, "edge_mutex_unlock").withPointerParameter("mutex", &api_mutex).andReturnValue(0);
    pt_device_create_with_feature_flags(active_connection->id, "some_device", 3600, NONE, PT_DEVICE_FEATURE_CERTIFICATE_RENEWAL, NULL);
    expect_msg_api_message();
    ValuePointer *value_pointer = expect_outgoing_data_frame(
                                                             "{\"id\":\"1\",\"jsonrpc\":\"2.0\",\"method\":\"write\",\"params\":{\"deviceId\":\"some_device\","
                                                             "\"objects\":[{\"objectId\":35011,\"objectInstances\":[{\"objectInstanceId\":0,\"resources\":[{"
                                                             "\"operations\":4,\"resourceId\":27002,\"type\":\"string\",\"value\":\"MTI4Ng==\"},{"
                                                             "\"operations\":1,\"resourceId\":27003,\"type\":\"opaque\",\"value\":\"\"}]}]}]}}"
                                                             );
    mh_expect_mutexing(&api_mutex);
    mh_expect_mutexing(&api_mutex);
    mh_expect_mutexing(&api_mutex);
    pt_status_t status = pt_device_certificate_renew_resource_callback(active_connection_id,
                                                                       "some_device",
                                                                       0, 0, 0, 0,
                                                                       (const uint8_t *) request_tlv_unknown_required_type,
                                                                       request_tlv_unknown_required_type_len, NULL);
    CHECK_EQUAL(PT_STATUS_SUCCESS, status);
    process_event_loop_send_message(true /* connection found */);
    receive_incoming_data_frame_expectations();
    find_client_device_expectations();
    receive_incoming_data_frame(active_connection, "{\"id\":\"1\",\"jsonrpc\":\"2.0\",\"result\":\"ok\"}");
    mock().checkExpectations();

    delete value_pointer;
}
