/* Implementation of the libevent internal structures */
#ifndef EVHTTP_MOCK_H_
#define EVHTTP_MOCK_H_
#include <event2/http.h>

struct evhttp_request {
    enum evhttp_cmd_type command;
};

struct evhttp {
    bool dummy;
};

struct evhttp_bound_socket {
    bool dummy;
};

struct evhttp_uri {
    bool dummy;
};
#endif
