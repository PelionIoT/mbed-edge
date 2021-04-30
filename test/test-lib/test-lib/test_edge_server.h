#ifndef TEST_EDGE_SERVER_H
#define TEST_EDGE_SERVER_H

#include "cpputest-custom-types/value_pointer.h"
extern "C" {
#include <stdbool.h>
#include <event2/event.h>
}

typedef enum {
    MAIN_TEST_INITIALIZES_SERVER_NO,
    MAIN_TEST_INITIALIZES_SERVER_YES
} main_test_server_init_param_e;

typedef enum {
    MAIN_TEST_EVENT_BASE_CREATION_FAILS,
    MAIN_TEST_EVENT_BASE_CREATION_SUCCEEDS
} main_test_event_base_creation_param_e;

typedef enum {
    MAIN_TEST_EXPECT_RESET_STORAGE_NO = false,
    MAIN_TEST_EXPECT_RESET_STORAGE_YES = true
} main_test_expected_reset_storage_e;

typedef struct main_test_params {
    struct evconnlistener *listener;
    struct evhttp *http;
    struct evhttp_bound_socket *http_socket;
    struct event_base *base;
    struct event *timer_event; // timer for cleaning out timed out JSON RPC requests
    struct lws_context_creation_info *info;
    int event_dispatch_return_value;
    ValuePointer *null_value_pointer;
    pthread_t *tester_thread;
    bool wait_in_event_loop;
    bool removing_old_socket_fails;
    bool old_socket_exists;
    bool acquiring_socket_lock_fails;
} main_test_params_t;

main_test_params_t *edge_server_alloc_main_test_params(
        main_test_event_base_creation_param_e event_base_creation_succeeds);
void edge_server_delete_main_test_params(main_test_params_t *params);
void edge_server_main_expectations_until_event_loop(int argc, char **argv, main_test_params_t *params);
void edge_server_main_expectations_after_event_loop(main_test_params_t *params);

#endif

