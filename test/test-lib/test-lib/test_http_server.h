#ifndef TEST_HTTP_SERVER_H
#define TEST_HTTP_SERVER_H

extern "C" {
#include <stdbool.h>
#include <event2/http.h>
}

void test_http_server_init_succeeds_expectations(struct evhttp *http,
                                                 struct evhttp_bound_socket *socket,
                                                 const char *address,
                                                 int32_t port);
#endif
