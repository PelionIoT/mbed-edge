#include "CppUTest/TestHarness.h"
#include "CppUTestExt/MockSupport.h"
#include "test-lib/evbuf_mock.h"
#include "edge-client/edge_client.h"

extern "C" {
#include "test-lib/evbase_mock.h"
#include <string.h>
#include <stdbool.h>

#include <event2/http.h>
#include <event2/bufferevent.h>
#include "edge-core/http_server.h"
#include "test-lib/evhttp_mock.h"
#include "edge-rpc/rpc.h"
}

#include "test-lib/MyEvBuffer.h"

#define DUMMY_SOCKET_HANDLE 100

TEST_GROUP(server_group) {
    void setup()
    {
    }

    void teardown()
    {
    }
};

static void clean_context_and_http(struct context *context, struct evhttp *http)
{
    free(context->ctx_data->http_server);
    free(context->ctx_data);
    evbase_mock_delete(context->ev_base);
    free(context);
    if (http) {
        free(http);
    }
}

static void create_event_loop(struct context *context, struct evhttp *http, struct event_base *base)
{
    context->ctx_data = (struct ctx_data *) calloc(1, sizeof(struct ctx_data));
    context->json_flags = JSON_COMPACT | JSON_SORT_KEYS;
    int http_port = 22500;

    mock().expectOneCall("edge_mutex_init")
            .withPointerParameter("mutex", &rpc_mutex)
            .withIntParameter("type", PTHREAD_MUTEX_ERRORCHECK)
            .andReturnValue(0);
    mock().expectOneCall("evthread_use_pthreads").andReturnValue(0);
    mock().expectOneCall("event_base_new").andReturnValue((void *) base);
    if (base) {
        mock().expectOneCall("evhttp_new").andReturnValue((void *) http);
        if (http) {
            mock().expectOneCall("evhttp_set_cb").andReturnValue(0);
            mock().expectOneCall("evhttp_set_gencb");
            mock().expectOneCall("evhttp_bind_socket_with_handle")
                    .withStringParameter("address", "127.0.0.1")
                    .withIntParameter("port", http_port)
                    .andReturnValue((void *) socket);
        }
    }
    if ((!http) && base) {
        mock().expectOneCall("event_base_free").withPointerParameter("base", base);
        evbase_mock_delete(base);
    }

    bool creation_succeeds = create_server_event_loop(context, http_port, (char*)"127.0.0.1");
    bool expected_succeeds = true;
    if (!base || !http) {
        expected_succeeds = false;
    }
    CHECK_EQUAL(expected_succeeds, creation_succeeds);
}

TEST(server_group, test_create_server_event_loop_succeeds)
{
    struct event_base *base = evbase_mock_new();
    struct evhttp *http = (struct evhttp *) calloc(1, sizeof(struct evhttp));
    struct context *context = (struct context *) calloc(1, sizeof(struct context));
    create_event_loop(context, http, base);
    clean_context_and_http(context, http);
    mock().checkExpectations();
}

TEST(server_group, test_create_server_event_loop_no_http)
{
    struct event_base *base = evbase_mock_new();
    struct context *context = (struct context *) calloc(1, sizeof(struct context));
    create_event_loop(context, NULL, base);
    clean_context_and_http(context, NULL);
    mock().checkExpectations();
}

TEST(server_group, test_create_server_event_loop_cannot_allocate_base)
{
    struct evhttp *http = (struct evhttp *) calloc(1, sizeof(struct evhttp));
    struct context *context = (struct context *) calloc(1, sizeof(struct context));
    create_event_loop(context, http, NULL);
    clean_context_and_http(context, http);
    mock().checkExpectations();
}
