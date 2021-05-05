#include "CppUTest/TestHarness.h"
#include "CppUTestExt/MockSupport.h"
#include "CppUTestExt/MockNamedValue.h"
#include "test-lib/evbase_mock.h"

extern "C" {
#include <string.h>
#include <stdbool.h>

#include <event2/http.h>
#include "test-lib/evhttp_mock.h"
}

#include "test-lib/MyEvBuffer.h"

extern "C" {
struct evhttp *evhttp_new(struct event_base *base)
{
    return (evhttp *) mock().actualCall("evhttp_new").returnPointerValue();
}

void evhttp_del_accept_socket(struct evhttp *http, struct evhttp_bound_socket *bound_socket)
{
    mock().actualCall("evhttp_del_accept_socket");
}

void evhttp_free(struct evhttp* http)
{
    mock().actualCall("evhttp_free");
}

int evhttp_set_cb(struct evhttp *http, const char *path, void (*cb)(struct evhttp_request *, void *), void *cb_arg)
{
    return mock().actualCall("evhttp_set_cb").returnIntValue();
}

void evhttp_set_gencb(struct evhttp *http, void (*cb)(struct evhttp_request *, void *), void *arg)
{
    mock().actualCall("evhttp_set_gencb");
}

struct evhttp_bound_socket *evhttp_bind_socket_with_handle(struct evhttp *http, const char *address, ev_uint16_t port)
{
    return (struct evhttp_bound_socket *) mock().actualCall("evhttp_bind_socket_with_handle").withStringParameter(
            "address", address).withIntParameter("port", port).returnPointerValue();
}

enum evhttp_cmd_type evhttp_request_get_command(const struct evhttp_request *req)
{
    mock().actualCall("evhttp_request_get_command");
    return req->command;
}

const char *evhttp_request_get_uri(const struct evhttp_request *req)
{
    return (const char *) mock().actualCall("evhttp_request_get_uri").returnPointerValue();
}

struct evhttp_uri *evhttp_uri_parse(const char *source_uri)
{
    return (evhttp_uri *) mock().actualCall("evhttp_uri_parse").returnPointerValue();
}

const char *evhttp_uri_get_query(const struct evhttp_uri *uri)
{
    return (const char *) mock().actualCall("evhttp_uri_get_query").returnPointerValue();
}

void evhttp_uri_free(struct evhttp_uri *uri)
{
    mock().actualCall("evhttp_uri_free");
}

struct evkeyvalq *evhttp_request_get_output_headers(struct evhttp_request *req)
{
    mock().actualCall("evhttp_request_get_output_headers");
    return NULL;
}

int evhttp_add_header(struct evkeyvalq *headers, const char *key, const char *value)
{
    mock().actualCall("evhttp_add_header").withStringParameter("key", key).withStringParameter("value", value);
    return 0;
}

const char *evhttp_find_header(const struct evkeyvalq *headers, const char *key)
{
    mock().actualCall("evhttp_find_header");
    return NULL;
}

void evhttp_send_reply(struct evhttp_request *req, int code, const char *reason, struct evbuffer *databuf)
{
    mock().actualCall("evhttp_send_reply")
            .withPointerParameter("req", (void *) req)
            .withIntParameter("code", code)
            .withStringParameter("reason", (const char *) reason)
            .withPointerParameter("databuf", (void *) databuf);
}
}
