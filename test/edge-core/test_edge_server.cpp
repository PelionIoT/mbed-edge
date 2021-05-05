#include <string.h>
#include <stdio.h>
#include <inttypes.h>
#include "libwebsockets.h"
#include "CppUTest/TestHarness.h"
#include "CppUTestExt/MockSupport.h"
#include "test-lib/test_http_server.h"
#include "test-lib/test_edge_server.h"
#include "cpputest-custom-types/value_pointer.h"
extern "C" {
#include "test-lib/evhttp_mock.h"
#include "test-lib/evbase_mock.h"
#include "edge-core/edge_server.h"
#include "edge-core/edge_device_object.h"
#include "common/websocket_comm.h"
#include "common/edge_mutex.h"
#include "edge-rpc/rpc_timeout_api.h"
#include "edge-core/protocol_crypto_api_internal.h"
}
#include "edge-client/edge_core_cb.h"
#include "common/edge_trace.h"

#define TEST_LOCK_FILE_DECRIPTOR_ID 20202

TEST_GROUP(edge_server) {
    void setup()
    {
    }

    void teardown()
    {
        edgeclient_create_params.reset_storage = false;
    }
};

TEST_GROUP(edge_server_with_program_context) {
    void setup()
    {
        create_program_context_and_data();
    }

    void teardown()
    {
        free_program_context_and_data();
    }
};

int dummy_callback(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len)
{
    return 0;
}

static struct lws_protocols protocols[] = {
    {
        "edge_protocol_translator",
        dummy_callback,
        sizeof(struct websocket_connection),
        2048,
    },
    { NULL, NULL, 0, 0 }
};

main_test_params_t *edge_server_alloc_main_test_params(
        main_test_event_base_creation_param_e event_base_creation_succeeds)
{
    struct evconnlistener *listener = (struct evconnlistener *) calloc(1, sizeof(evconnlistener));
    struct evhttp *http = (struct evhttp *) calloc(1, sizeof(struct evhttp));
    struct evhttp_bound_socket *http_socket =
            (struct evhttp_bound_socket *) calloc(1, sizeof(struct evhttp_bound_socket));
    struct event_base *base = NULL;
    if (MAIN_TEST_EVENT_BASE_CREATION_SUCCEEDS == event_base_creation_succeeds) {
        base = evbase_mock_new();
    }

    main_test_params_t *params = (main_test_params_t *) calloc(1, sizeof(main_test_params_t));
    params->listener = listener;
    params->timer_event = (struct event *) calloc(1, sizeof(struct event));
    params->http = http;
    params->http_socket = http_socket;
    params->base = base;
    params->null_value_pointer = new ValuePointer((uint8_t *) NULL, 0);
    return params;
}

void edge_server_delete_main_test_params(main_test_params_t *params)
{
    free(params->listener);
    free(params->http);
    free(params->http_socket);
    free(params->info);
    free(params->timer_event);
    delete params->null_value_pointer;
    if (params->tester_thread) {
        evbase_mock_release_interrupt_thread(params->base);
        pthread_join(*(params->tester_thread), NULL);
        free(params->tester_thread);
    }
    evbase_mock_delete(params->base);
    free(params);
}

struct lws_context_creation_info *fill_context_creation_info(struct event_base *base)
{
    void *foreign_loops[1];

    struct lws_context_creation_info *info = (struct lws_context_creation_info*)calloc(1, sizeof(struct lws_context_creation_info));;
    //memset(&info, 0, sizeof (struct lws_context_creation_info));
    int opts = 0;
    info->port = 7681;
    info->iface = "test_socket";
    info->protocols = protocols;
    info->extensions = NULL;
    info->ssl_cert_filepath = NULL;
    info->ssl_private_key_filepath = NULL;
    info->gid = -1;
    info->uid = -1;
    info->max_http_header_pool = 1;
    info->options = opts | LWS_SERVER_OPTION_LIBEVENT | LWS_SERVER_OPTION_UNIX_SOCK;
    foreign_loops[0] = base;
    info->foreign_loops = foreign_loops;

    return info;
}

void edge_server_main_expectations_until_event_loop(int argc, char **argv, main_test_params *params)
{
    static int lock_fd = TEST_LOCK_FILE_DECRIPTOR_ID;
    static int invalid_lock_fd = -1;
    // struct evconnlistener *listener = params->listener;
    struct evhttp *http = params->http;
    struct evhttp_bound_socket *http_socket = params->http_socket;
    struct event_base *base = params->base;
    params->info = fill_context_creation_info(base);

    mock().expectOneCall("edge_mutex_init")
            .withPointerParameter("mutex", &trace_mutex)
            .withIntParameter("type", PTHREAD_MUTEX_RECURSIVE)
            .andReturnValue(0);
    mock().expectOneCall("edge_mutex_init")
            .withPointerParameter("mutex", &rpc_mutex)
            .withIntParameter("type", PTHREAD_MUTEX_ERRORCHECK)
            .andReturnValue(0);
    mock().expectOneCall("evthread_use_pthreads").andReturnValue(0);
    mock().expectOneCall("event_base_new").andReturnValue((void *) base);
    if (base) {
        test_http_server_init_succeeds_expectations(http, http_socket, "127.0.0.1", 8080);
        struct event *timer_event = params->timer_event;
        timer_event->base = base;
        mock().expectOneCall("event_new")
                .withPointerParameter("base", base)
                .withIntParameter("fd", -1)
                .withIntParameter("flags", EV_PERSIST)
                .withPointerParameter("callback_fn", (void *) handle_timed_out_requests)
                .andReturnValue(timer_event);
        mock().expectOneCall("event_add").andReturnValue(0);

        byoc_data_t byoc_data;
        mock().expectOneCall("edgeclient_create_byoc_data")
            .withPointerParameter("cbor_file", NULL)
            .andReturnValue(&byoc_data);

        mock().expectOneCall("edgeclient_create")
            .withPointerParameter("params", &edgeclient_create_params)
            .withPointerParameter("byoc_data", &byoc_data);
        mock().expectOneCall("rfs_add_factory_reset_resource");
        mock().expectOneCall("edgeclient_connect");
        mock().expectOneCall("eventOS_scheduler_mutex_wait");
        mock().expectOneCall("eventOS_event_handler_create")
                .withPointerParameter("handler_func_ptr", (void *) crypto_api_event_handler)
                .withIntParameter("init_event_type", CRYPTO_API_EVENT_INIT)
                .andReturnValue(1); // tasklet id
        mock().expectOneCall("eventOS_scheduler_mutex_release");
        mock().expectOneCall("lws_set_log_level");
        mock().expectOneCall("edge_io_acquire_lock_for_socket")
                .withStringParameter("path", "TEST_UNIX_SOCKET_PATH")
                .withOutputParameterReturning("lock_fd",
                                              ((params->acquiring_socket_lock_fails) ? (&invalid_lock_fd) : (&lock_fd)),
                                              sizeof(int))
                .andReturnValue(params->acquiring_socket_lock_fails ? false : true);
        if (!params->acquiring_socket_lock_fails)  {
            mock().expectOneCall("edge_io_file_exists")
                    .withStringParameter("path", "TEST_UNIX_SOCKET_PATH")
                    .andReturnValue(params->old_socket_exists);
            if (params->old_socket_exists) {
                mock().expectOneCall("edge_io_unlink")
                        .withStringParameter("path", "TEST_UNIX_SOCKET_PATH")
                        .andReturnValue(params->removing_old_socket_fails ? -1 : 0);
            }
            if (!params->removing_old_socket_fails) {
                mock().expectOneCall("lws_create_context");
                mock().expectOneCall("event_base_dispatch")
                        .withPointerParameter("base", base)
                        .andReturnValue(params->event_dispatch_return_value);
            }
        }
    }
}
void edge_server_main_expectations_after_event_loop(main_test_params_t *params)
{
    // starts to clean up
    if (params->wait_in_event_loop) {
        mock().expectOneCall("edgeclient_stop").andReturnValue(1);
    }
    if (params->base) {
        if (params->timer_event) {
            mock().expectOneCall("event_del").withPointerParameter("ev", params->timer_event).andReturnValue(0);
            mock().expectOneCall("event_free").withPointerParameter("ev", params->timer_event);
        }
        if (!params->acquiring_socket_lock_fails) {
            if (!params->removing_old_socket_fails) {
                mock().expectOneCall("lws_context_destroy");
            }
            mock().expectOneCall("edge_io_release_lock_for_socket")
                    .withStringParameter("path", "TEST_UNIX_SOCKET_PATH")
                    .withIntParameter("lock_fd", TEST_LOCK_FILE_DECRIPTOR_ID)
                    .andReturnValue(true);
            mock().expectOneCall("edge_io_unlink")
                    .withStringParameter("path", "TEST_UNIX_SOCKET_PATH")
                    .andReturnValue(params->removing_old_socket_fails ? -1 : 0);
        }
        mock().expectOneCall("evhttp_del_accept_socket");
        mock().expectOneCall("evhttp_free");
        //mock().expectOneCall("evconnlistener_free")
        //        .withPointerParameter("lev", (void *) params->listener);
        mock().expectOneCall("event_base_free")
                .withPointerParameter("base", (void *) params->base);
    }
    mock().expectOneCall("edgeclient_destroy");
    mock().expectOneCall("edge_mutex_lock").withPointerParameter("mutex", (void *) &rpc_mutex).andReturnValue(0);
    mock().expectOneCall("edge_mutex_unlock").withPointerParameter("mutex", (void *) &rpc_mutex).andReturnValue(0);
    mock().expectOneCall("edge_mutex_destroy").withPointerParameter("mutex", (void *) &rpc_mutex).andReturnValue(0);
    mock().expectOneCall("libevent_global_shutdown");
    mock().expectOneCall("edge_mutex_destroy").withPointerParameter("mutex", (void *) &trace_mutex).andReturnValue(0);
}

static void *interrupt_thread(void *param)
{
    main_test_params_t *parameter = (main_test_params_t *) param;
    struct event_base *base = parameter->base;
    evbase_mock_wait_until_event_loop(base);
    shutdown_handler(0,0,NULL);
    evbase_mock_release_event_loop_lock_and_block_interrupt(base);
    return NULL;
}

static void main_test(const char *extra_parameter,
                      main_test_server_init_param_e initializes_server,
                      int expected_rc,
                      main_test_event_base_creation_param_e event_base_creation_succeeds,
                      main_test_expected_reset_storage_e expected_reset_storage,
                      int event_dispatch_return_value,
                      bool wait_in_event_loop,
                      bool removing_socket_fails,
                      bool acquiring_lock_for_socket_fails)
{
    mock().strictOrder();
#define ARG_COUNT 6
    const char *argv[ARG_COUNT] = {"edge-core", "-p", "TEST_UNIX_SOCKET_PATH", "-o", "8080", extra_parameter};
    int32_t argc = ARG_COUNT;
    int rc;
    main_test_params_t *params = edge_server_alloc_main_test_params(event_base_creation_succeeds);
    params->event_dispatch_return_value = event_dispatch_return_value;
    params->wait_in_event_loop = wait_in_event_loop;
    params->removing_old_socket_fails = removing_socket_fails;
    params->acquiring_socket_lock_fails = acquiring_lock_for_socket_fails;
    if (removing_socket_fails) {
        params->old_socket_exists = true;
    }
    if (wait_in_event_loop) {
        params->tester_thread = (pthread_t *) calloc(1, sizeof(pthread_t));
        evbase_mock_setup_event_loop_wait(params->base);
        pthread_create(params->tester_thread, NULL, interrupt_thread, (void *) params);
    }

    CHECK_EQUAL(false, edgeclient_create_params.reset_storage);
    if (MAIN_TEST_INITIALIZES_SERVER_YES == initializes_server) {
        edge_server_main_expectations_until_event_loop(argc, (char **) argv, params);
        edge_server_main_expectations_after_event_loop(params);
    }

    rc = testable_main((int) argc, (char **) argv);
    CHECK_EQUAL(expected_rc, rc);
    CHECK_EQUAL(expected_reset_storage, edgeclient_create_params.reset_storage);
    edge_server_delete_main_test_params(params);
    mock().checkExpectations();
}

TEST(edge_server, test_edge_server_main)
{
    main_test("-r",
              MAIN_TEST_INITIALIZES_SERVER_YES,
              0 /* expected_rc */,
              MAIN_TEST_EVENT_BASE_CREATION_SUCCEEDS,
              MAIN_TEST_EXPECT_RESET_STORAGE_YES,
              0 /* event_dispatch_return_value */,
              false /* wait_in_event_loop */,
              false /* removing_socket_fails */,
              false /* acquire_lock_for_socket_fails */);
}

TEST(edge_server, test_edge_server_main_removing_old_socket_fails)
{
    main_test("-r",
              MAIN_TEST_INITIALIZES_SERVER_YES,
              0 /* expected_rc */,
              MAIN_TEST_EVENT_BASE_CREATION_SUCCEEDS,
              MAIN_TEST_EXPECT_RESET_STORAGE_YES,
              0 /* event_dispatch_return_value */,
              false /* wait_in_event_loop */,
              true /* removing_socket_fails */,
              false /* acquire_lock_for_socket_fails */);
}

TEST(edge_server, test_edge_server_main_acquiring_lock_for_socket_fails)
{
    main_test("-r",
              MAIN_TEST_INITIALIZES_SERVER_YES,
              0 /* expected_rc */,
              MAIN_TEST_EVENT_BASE_CREATION_SUCCEEDS,
              MAIN_TEST_EXPECT_RESET_STORAGE_YES,
              0 /* event_dispatch_return_value */,
              false /* wait_in_event_loop */,
              false /* removing_socket_fails */,
              true /* acquire_lock_for_socket_fails */);
}

TEST(edge_server, test_edge_server_main_event_dispatch_returns_error)
{
    main_test("--reset-storage",
              MAIN_TEST_INITIALIZES_SERVER_YES,
              1 /* expected_rc */,
              MAIN_TEST_EVENT_BASE_CREATION_SUCCEEDS,
              MAIN_TEST_EXPECT_RESET_STORAGE_YES,
              1 /* event_dispatch_return_value */,
              false /* wait_in_event_loop */,
              false /* removing_socket_fails */,
              false /* acquire_lock_for_socket_fails */);
}

TEST(edge_server, test_edge_server_cannot_allocate_base)
{
    main_test("--reset-storage",
              MAIN_TEST_INITIALIZES_SERVER_YES,
              1 /* expected_rc */,
              MAIN_TEST_EVENT_BASE_CREATION_FAILS,
              MAIN_TEST_EXPECT_RESET_STORAGE_YES,
              0 /* event_dispatch_return_value */,
              false /* wait_in_event_loop */,
              false /* removing_socket_fails */,
              false /* acquire_lock_for_socket_fails */);
}

TEST(edge_server, test_shutdown_handler)
{
    // give the interrupt signal
    main_test("-r",
              MAIN_TEST_INITIALIZES_SERVER_YES,
              0 /* expected_rc */,
              MAIN_TEST_EVENT_BASE_CREATION_SUCCEEDS,
              MAIN_TEST_EXPECT_RESET_STORAGE_YES,
              0 /* event_dispatch_return_value */,
              true /* wait_in_event_loop */,
              false /* removing_socket_fails */,
              false /* acquire_lock_for_socket_fails */);
}

TEST(edge_server_with_program_context, test_edge_server_get_base)
{
    CHECK(NULL == edge_server_get_base());
    mock().checkExpectations();
}

TEST(edge_server_with_program_context, test_rfs_customer_code_succeeded)
{
    edgeserver_rfs_customer_code_succeeded();
    mock().checkExpectations();
}

TEST(edge_server_with_program_context, test_trace_mutext_wait_and_release)
{
    mock().expectOneCall("edge_mutex_lock").withPointerParameter("mutex", (void *) &trace_mutex).andReturnValue(0);
    trace_mutex_wait();
    mock().expectOneCall("edge_mutex_unlock").withPointerParameter("mutex", (void *) &trace_mutex).andReturnValue(0);
    trace_mutex_release();
    mock().checkExpectations();
}
