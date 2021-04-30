#include "CppUTest/TestHarness.h"
#include "CppUTestExt/MockSupport.h"
#include "test-lib/evbase_mock.h"
#include "test-lib/evbuf_mock.h"
#include "cpputest-custom-types/value_pointer.h"
#include "test-lib/test_http_server.h"

extern "C" {

#include <string.h>
#include <stdbool.h>

#include <event2/http.h>
#include <event2/bufferevent.h>
#include "edge-core/http_server.h"
#include "edge-core/server.h"
#include "test-lib/evhttp_mock.h"
#include "edge_version_info.h"
}

#include "test-lib/MyEvBuffer.h"

struct context ctx;
struct ctx_data ctx_data;

void check_ok_response_headers()
{
    mock().expectOneCall("evhttp_request_get_output_headers");
    mock().expectOneCall("evhttp_add_header")
        .withStringParameter("key", "Content-Type").withStringParameter("value", "application/json");
    mock().expectOneCall("evhttp_request_get_output_headers");
    mock().expectOneCall("evhttp_add_header")
        .withStringParameter("key", "Charset")
        .withStringParameter("value", "utf-8");
}

static void check_allow_header()
{
    mock().expectOneCall("evhttp_request_get_output_headers");
    mock().expectOneCall("evhttp_add_header")
        .withStringParameter("key", "Allow")
        .withStringParameter("value", "GET");
}

TEST_GROUP(http_server_group) {
    void setup()
    {
        memset(&ctx, 0, sizeof(struct context));
        memset(&ctx_data, 0, sizeof(struct ctx_data));
        ctx.ctx_data = &ctx_data;
    }

    void teardown()
    {
    }
};

void test_http_server_init_succeeds_expectations(struct evhttp *http,
                                                 struct evhttp_bound_socket *socket,
                                                 const char *address,
                                                 int32_t port
                                                 )
{
    mock().expectOneCall("evhttp_new").andReturnValue((void *) http);
    mock().expectOneCall("evhttp_set_cb").andReturnValue(0);
    mock().expectOneCall("evhttp_set_gencb");
    mock().expectOneCall("evhttp_bind_socket_with_handle")
            .withStringParameter("address", address)
            .withIntParameter("port", port)
            .andReturnValue((void *) socket);
}

TEST(http_server_group, test_http_server_init_when_everything_succeeds)
{
    struct evhttp *http = (struct evhttp *) calloc(1, sizeof(struct evhttp));
    struct evhttp_bound_socket *socket = (struct evhttp_bound_socket *) calloc(1, sizeof(struct evhttp_bound_socket));
    test_http_server_init_succeeds_expectations(http, socket, "127.0.0.1", 22500);
    bool init_succeeds = http_server_init(&ctx, 22500);
    CHECK_EQUAL(true, init_succeeds);
    free(http);
    free(socket);
    free(ctx_data.http_server);
    mock().checkExpectations();
}

TEST(http_server_group, test_http_server_create_set_cb_fails)
{
    struct evhttp *http = (struct evhttp *) calloc(1, sizeof(struct evhttp));
    mock().expectOneCall("evhttp_new").andReturnValue((void *) http);
    mock().expectOneCall("evhttp_set_cb").andReturnValue(1);
    mock().expectOneCall("evhttp_free");
    bool init_succeeds = http_server_init(&ctx, 22500);
    CHECK_EQUAL(false, init_succeeds);
    mock().checkExpectations();
    free(http);
}

TEST(http_server_group, test_http_server_create_bind_socket_fails)
{
    struct evhttp *http = (struct evhttp *) calloc(1, sizeof(struct evhttp));
    mock().expectOneCall("evhttp_new").andReturnValue((void *) http);
    mock().expectOneCall("evhttp_set_cb").andReturnValue(0);
    mock().expectOneCall("evhttp_set_gencb");
    mock().expectOneCall("evhttp_bind_socket_with_handle")
        .withStringParameter("address", "127.0.0.1")
        .withIntParameter("port", 22500).andReturnValue((void *) NULL);
    mock().expectOneCall("evhttp_free");
    bool init_succeeds = http_server_init(&ctx, 22500);
    CHECK_EQUAL(false, init_succeeds);
    mock().checkExpectations();
    free(http);
}

TEST(http_server_group, test_http_server_create_evhttp_fails)
{
    mock().expectOneCall("evhttp_new").andReturnValue((void *) NULL);
    bool init_succeeds = http_server_init(&ctx, 22500);
    CHECK_EQUAL(false, init_succeeds);
    mock().checkExpectations();
}

TEST(http_server_group, test_http_server_clean)
{
    ctx_data.http_server = (struct http_server *) calloc(1, sizeof(struct http_server));
    struct http_server *server = ctx_data.http_server;
    server->http = (struct evhttp *) calloc(1, sizeof(struct evhttp));
    struct evhttp *http = server->http;
    struct evhttp_bound_socket *socket = server->bound_socket =
            (struct evhttp_bound_socket *) calloc(1, sizeof(struct evhttp_bound_socket));
    mock().expectOneCall("evhttp_del_accept_socket");
    mock().expectOneCall("evhttp_free");
    http_server_clean(&server);
    mock().checkExpectations();
    free(http);
    free(socket);
}

TEST(http_server_group, test_generic_request_cb)
{
    struct evhttp_request req;
    MyEvBuffer expectedBody = MyEvBuffer((char *) "");
    MyEvBufferComparator comparator;
    struct evbuffer bev = { 0 };
    mock().installComparator("MyEvBuffer", comparator);
    mock().expectOneCall("evbuffer_new").andReturnValue((void *) &bev);
    mock().expectOneCall("evhttp_send_reply")
            .withPointerParameter("req", (void *) &req)
            .withIntParameter("code", 404)
            .withStringParameter("reason", "Not found")
            .withPointerParameter("databuf", (void *) &bev);
    mock().expectOneCall("evbuffer_free")
        .withPointerParameter("buf", (void *) &bev);
    generic_request_cb(&req, (void *) NULL);
    mock().checkExpectations();
}

TEST(http_server_group, test_status_request_cb_returns_correct_reply_when_connected_and_request_type_is_get)
{
    (ctx.ctx_data)->cloud_connection_status = EDGE_STATE_CONNECTED;
    ctx.json_flags = JSON_COMPACT | JSON_SORT_KEYS;
    struct evhttp_request req;
    struct evbuffer evbuf = { 0 };
    struct evhttp_uri *parsed_uri = (struct evhttp_uri *) calloc(1, sizeof(struct evhttp_uri));
    memset(&req, 0, sizeof(struct evhttp_request));
    req.command = EVHTTP_REQ_GET;
    MyEvBufferComparator comparator;
    mock().installComparator("MyEvBuffer", comparator);
    MyEvBuffer expectedBody = MyEvBuffer((char *) "{\"account-id\":\"account-id\",\"edge-version\":\""VERSION_STRING"\",\"endpoint-name\":\"endpoint-name\",\"internal-id\":\"internal-id\",\"lwm2m-server-uri\":\"lwm2m-server-uri\",\"status\":\"connected\"}");
    mock().expectOneCall("evhttp_request_get_uri").andReturnValue((void *) "/status");
    check_ok_response_headers();
    mock().expectOneCall("evbuffer_new").andReturnValue((void *) &evbuf);
    mock().expectOneCall("evhttp_uri_parse").andReturnValue((void *) parsed_uri);
    mock().expectOneCall("evhttp_uri_free");
    mock().expectOneCall("evhttp_uri_get_query").andReturnValue((void *) NULL);
    mock().expectOneCall("evhttp_request_get_command");
    mock().expectOneCall("evbuffer_add")
            .withPointerParameter("buf", (void *) &evbuf)
            .withParameterOfType("MyEvBuffer", "data", &expectedBody)
            .andReturnValue(0);
    mock().expectOneCall("evhttp_send_reply")
            .withPointerParameter("req", (void *) &req)
            .withIntParameter("code", 200)
            .withStringParameter("reason", "OK")
            .withPointerParameter("databuf", &evbuf);
    mock().expectOneCall("get_internal_id").andReturnValue("internal-id");
    mock().expectOneCall("get_endpoint_name").andReturnValue("endpoint-name");
    mock().expectOneCall("get_account_id").andReturnValue("account-id");
    mock().expectOneCall("get_lwm2m_server_uri").andReturnValue("lwm2m-server-uri");
    mock().expectOneCall("evbuffer_free").withPointerParameter("buf", (void *) &evbuf);
    status_request_cb(&req, (void *) (&ctx));
    mock().checkExpectations();
    free(parsed_uri);
}

TEST(http_server_group, test_status_request_cb_returns_correct_reply_when_uri_cannot_be_parsed)
{
    (ctx.ctx_data)->cloud_connection_status = EDGE_STATE_CONNECTED;
    struct evhttp_request req;
    struct evbuffer evbuf = { 0 };
    memset(&req, 0, sizeof(struct evhttp_request));
    req.command = EVHTTP_REQ_GET;
    MyEvBufferComparator comparator;
    mock().installComparator("MyEvBuffer", comparator);
    MyEvBuffer expectedBody = MyEvBuffer((char *) "");
    mock().expectOneCall("evhttp_request_get_uri").andReturnValue((void *) "/status");
    mock().expectOneCall("evbuffer_new").andReturnValue((void *) &evbuf);
    mock().expectOneCall("evhttp_uri_parse").andReturnValue((void *)NULL);
    mock().expectOneCall("evhttp_send_reply")
            .withPointerParameter("req", (void *) &req)
            .withIntParameter("code", 400)
            .withStringParameter("reason", "Bad request")
            .withPointerParameter("databuf", &evbuf);
    mock().expectOneCall("evbuffer_free").withPointerParameter("buf", (void *) &evbuf);
    status_request_cb(&req, (void *) (&ctx));
    mock().checkExpectations();
}

TEST(http_server_group, test_status_request_cb_returns_correct_reply_when_connecting_and_request_type_is_get)
{
    (ctx.ctx_data)->cloud_connection_status = EDGE_STATE_CONNECTING;
    ctx.json_flags = JSON_COMPACT | JSON_SORT_KEYS;
    struct evbuffer evbuf = { 0 };
    struct evhttp_request req;
    struct evhttp_uri *parsed_uri = (struct evhttp_uri *) calloc(1, sizeof(struct evhttp_uri));
    memset(&req, 0, sizeof(struct evhttp_request));
    req.command = EVHTTP_REQ_GET;
    MyEvBufferComparator comparator;
    mock().installComparator("MyEvBuffer", comparator);
    MyEvBuffer expectedBody = MyEvBuffer((char *) "{\"account-id\":\"account-id\",\"edge-version\":\""VERSION_STRING"\",\"endpoint-name\":\"endpoint-name\",\"internal-id\":\"internal-id\",\"lwm2m-server-uri\":\"lwm2m-server-uri\",\"status\":\"connecting\"}");
    mock().expectOneCall("evhttp_request_get_uri").andReturnValue((void *) "/status");
    check_ok_response_headers();
    mock().expectOneCall("evbuffer_new").andReturnValue((void *) &evbuf);
    mock().expectOneCall("evhttp_uri_parse").andReturnValue((void *) parsed_uri);
    mock().expectOneCall("evhttp_uri_free");
    mock().expectOneCall("evhttp_uri_get_query").andReturnValue((void *) NULL);
    mock().expectOneCall("evhttp_request_get_command");
    mock().expectOneCall("evbuffer_add")
            .withPointerParameter("buf", (void *) &evbuf)
            .withParameterOfType("MyEvBuffer", "data", &expectedBody);
    mock().expectOneCall("evhttp_send_reply")
            .withPointerParameter("req", (void *) &req)
            .withIntParameter("code", 200)
            .withStringParameter("reason", "OK")
            .withPointerParameter("databuf", &evbuf);
    mock().expectOneCall("get_internal_id").andReturnValue("internal-id");
    mock().expectOneCall("get_endpoint_name").andReturnValue("endpoint-name");
    mock().expectOneCall("get_account_id").andReturnValue("account-id");
    mock().expectOneCall("get_lwm2m_server_uri").andReturnValue("lwm2m-server-uri");
    mock().expectOneCall("evbuffer_free").withPointerParameter("buf", (void *) &evbuf);
    status_request_cb(&req, (void *) (&ctx));
    mock().checkExpectations();
    free(parsed_uri);
}

TEST(http_server_group, test_status_request_cb_returns_correct_reply_when_in_error_state)
{
    (ctx.ctx_data)->cloud_connection_status = EDGE_STATE_ERROR;
    ctx.json_flags = JSON_COMPACT | JSON_SORT_KEYS;
    ctx.ctx_data->cloud_error = (struct cloud_error *) calloc(1, sizeof(struct cloud_error));
    ctx.ctx_data->cloud_error->error_description = (char *) "Client in reconnection mode DnsResolvingFailed";
    ctx.ctx_data->cloud_error->error_code = 12;
    struct evhttp_request req;
    struct evbuffer evbuf = { 0 };
    struct evhttp_uri *parsed_uri = (struct evhttp_uri *) calloc(1, sizeof(struct evhttp_uri));
    memset(&req, 0, sizeof(struct evhttp_request));
    req.command = EVHTTP_REQ_GET;
    MyEvBufferComparator comparator;
    mock().installComparator("MyEvBuffer", comparator);
    MyEvBuffer expectedBody = MyEvBuffer((char *) "{\"account-id\":\"account-id\",\"edge-version\":\""VERSION_STRING"\",\"endpoint-name\":\"endpoint-name\","
            "\"error_code\":12,\"error_description\":\"Client in reconnection mode DnsResolvingFailed\",\"internal-id\":\"internal-id\",\"lwm2m-server-uri\":\"lwm2m-server-uri\",\"status\":\"error\"}");
    mock().expectOneCall("evhttp_request_get_uri").andReturnValue((void *) "/status");
    mock().expectOneCall("evbuffer_new").andReturnValue((void *) &evbuf);
    check_ok_response_headers();
    mock().expectOneCall("evhttp_uri_parse").andReturnValue((void *) parsed_uri);
    mock().expectOneCall("evhttp_uri_free");
    mock().expectOneCall("evhttp_uri_get_query").andReturnValue((void *) NULL);
    mock().expectOneCall("evhttp_request_get_command");
    mock().expectOneCall("evbuffer_add")
            .withPointerParameter("buf", (void *) &evbuf)
            .withParameterOfType("MyEvBuffer", "data", &expectedBody)
            .andReturnValue(0);
    mock().expectOneCall("evhttp_send_reply")
            .withPointerParameter("req", (void *) &req)
            .withIntParameter("code", 200)
            .withStringParameter("reason", "OK")
            .withPointerParameter("databuf", &evbuf);
    mock().expectOneCall("get_internal_id").andReturnValue("internal-id");
    mock().expectOneCall("get_endpoint_name").andReturnValue("endpoint-name");
    mock().expectOneCall("get_account_id").andReturnValue("account-id");
    mock().expectOneCall("get_lwm2m_server_uri").andReturnValue("lwm2m-server-uri");
    mock().expectOneCall("evbuffer_free").withPointerParameter("buf", (void *) &evbuf);
    status_request_cb(&req, (void *) (&ctx));
    mock().checkExpectations();
    free(ctx.ctx_data->cloud_error);
    free(parsed_uri);
}

TEST(http_server_group, test_status_request_cb_returns_correct_reply_when_request_type_is_not_get)
{

    (ctx.ctx_data)->cloud_connection_status = EDGE_STATE_CONNECTING;
    struct evhttp_request req;
    struct evbuffer evbuf = { 0 };
    struct evhttp_uri *parsed_uri = (struct evhttp_uri *) calloc(1, sizeof(struct evhttp_uri));
    memset(&req, 0, sizeof(struct evhttp_request));
    req.command = EVHTTP_REQ_POST;
    MyEvBufferComparator comparator;
    MyEvBuffer expectedBody = MyEvBuffer((char *) "");
    mock().installComparator("MyEvBuffer", comparator);
    mock().expectOneCall("evhttp_request_get_uri").andReturnValue((void *) "/status");
    mock().expectOneCall("evbuffer_new").andReturnValue((void *) &evbuf);
    check_allow_header();
    mock().expectOneCall("evhttp_uri_parse").andReturnValue((void *) parsed_uri);
    mock().expectOneCall("evhttp_uri_free");
    mock().expectOneCall("evhttp_uri_get_query").andReturnValue((void *) NULL);
    mock().expectOneCall("evhttp_request_get_command");
    mock().expectOneCall("evhttp_send_reply")
            .withPointerParameter("req", (void *) &req)
            .withIntParameter("code", 405)
            .withStringParameter("reason", "Method not allowed")
            .withPointerParameter("databuf", &evbuf);
    mock().expectOneCall("evbuffer_free").withPointerParameter("buf", (void *) &evbuf);
    status_request_cb(&req, (void *) (&ctx));
    mock().checkExpectations();
    free(parsed_uri);
}

TEST(http_server_group, test_status_request_cb_returns_correct_reply_when_request_is_badly_formed)
{
    (ctx.ctx_data)->cloud_connection_status = EDGE_STATE_CONNECTING;
    struct evhttp_request req;
    struct evbuffer evbuf = { 0 };
    struct evhttp_uri *parsed_uri = (struct evhttp_uri *) calloc(1, sizeof(struct evhttp_uri));
    memset(&req, 0, sizeof(struct evhttp_request));
    req.command = EVHTTP_REQ_GET;
    MyEvBufferComparator comparator;
    MyEvBuffer expectedBody = MyEvBuffer((char *) "");
    mock().installComparator("MyEvBuffer", comparator);
    mock().expectOneCall("evhttp_request_get_uri").andReturnValue((void *) "/status?foo=bar");
    mock().expectOneCall("evbuffer_new").andReturnValue((void *) &evbuf);
    mock().expectOneCall("evhttp_uri_parse").andReturnValue((void *) parsed_uri);
    mock().expectOneCall("evhttp_uri_free");
    mock().expectOneCall("evhttp_uri_get_query").andReturnValue((void *) "foo=bar");
    mock().expectOneCall("evhttp_send_reply")
            .withPointerParameter("req", (void *) &req)
            .withIntParameter("code", 400)
            .withStringParameter("reason", "Bad request")
            .withPointerParameter("databuf", &evbuf);
    mock().expectOneCall("evbuffer_free").withPointerParameter("buf", (void *) &evbuf);
    status_request_cb(&req, (void *) (&ctx));
    mock().checkExpectations();
    free(parsed_uri);
}

TEST(http_server_group, test_status_request_cb_returns_undefined_reply_when_connection_status_is_undefined)
{
    (ctx.ctx_data)->cloud_connection_status = static_cast<edge_state>(-1);
    ctx.json_flags = JSON_COMPACT | JSON_SORT_KEYS;
    struct evhttp_request req;
    struct evhttp_uri *parsed_uri = (struct evhttp_uri *) calloc(1, sizeof(struct evhttp_uri));
    struct evbuffer *evbuf = (struct evbuffer *) calloc(1, sizeof(struct evbuffer));
    memset(&req, 0, sizeof(struct evhttp_request));
    req.command = EVHTTP_REQ_GET;
    MyEvBufferComparator comparator;
    mock().installComparator("MyEvBuffer", comparator);
    MyEvBuffer expectedBody = MyEvBuffer(
            (char *) "{\"account-id\":\"account-id\",\"edge-version\":\""VERSION_STRING"\",\"endpoint-name\":\"endpoint-name\",\"internal-id\":\"internal-id\",\"lwm2m-server-uri\":\"lwm2m-server-uri\",\"status\":\"undefined\"}");
    mock().expectOneCall("evbuffer_new").andReturnValue(evbuf);
    mock().expectOneCall("evhttp_request_get_uri").andReturnValue((void *) "/status");
    check_ok_response_headers();
    mock().expectOneCall("evhttp_uri_parse").andReturnValue((void *) parsed_uri);
    mock().expectOneCall("evhttp_uri_free");
    mock().expectOneCall("evhttp_uri_get_query").andReturnValue((void *) NULL);
    mock().expectOneCall("evhttp_request_get_command");
    mock().expectOneCall("evbuffer_add")
            .withPointerParameter("buf", (void *) evbuf)
            .withParameterOfType("MyEvBuffer", "data", &expectedBody)
            .andReturnValue(0);
    mock().expectOneCall("evhttp_send_reply")
            .withPointerParameter("req", &req)
            .withIntParameter("code", 200)
            .withStringParameter("reason", "OK")
            .withPointerParameter("databuf", (void *) evbuf);
    mock().expectOneCall("get_internal_id").andReturnValue("internal-id");
    mock().expectOneCall("get_endpoint_name").andReturnValue("endpoint-name");
    mock().expectOneCall("get_account_id").andReturnValue("account-id");
    mock().expectOneCall("get_lwm2m_server_uri").andReturnValue("lwm2m-server-uri");
    mock().expectOneCall("evbuffer_free").withPointerParameter("buf", evbuf);
    status_request_cb(&req, (void *) (&ctx));
    mock().checkExpectations();
    free(evbuf);
    free(parsed_uri);
}
