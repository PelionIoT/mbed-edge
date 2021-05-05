#include "CppUTest/TestHarness.h"
#include "CppUTestExt/MockSupport.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <jansson.h>

// For sleeping in the generic handler
#include <time.h>

extern "C" {
#include "ns_list.h"
#include "edge-rpc/rpc.h"
#include "jsonrpc/jsonrpc.h"
#include "common/integer_length.h"
#include "test-lib/evbase_mock.h"
#include "edge-rpc/rpc_timeout_api.h"
}
#include "test-lib/json_pointer.h"
#include "test-lib/json_message_t_pointer.h"
#include "test-lib/rpc_mocks.h"

struct rpc_request_context {
    bool dummy;
};

static uint32_t counter = 0;

struct connection {
    bool dummy;
};

static char* format_msg_id(uint32_t the_id)
{
    char *id = (char*) calloc(edge_int_length(the_id) + 1, sizeof(char));
    sprintf(id, "%d", the_id);
    return id;
}

/**
 * \brief Default message generation function.
 * \return Numeric ascending message ids are generated and returned
 * as character array
 */
static char* test_generate_msg_id()
{
    // move counter up before creating id
    // same id as the current when just formatting
    counter++;
    char *id = format_msg_id(counter);
    return id;
}

static void reset_counter()
{
    counter = 0;
}

struct jsonrpc_method_entry_t method_table[] = {
    { "test", rpc_test_handler_success, "o" },
    { "test-error", rpc_test_handler_error, "o"},
    { NULL, NULL, "o" }
};

TEST_GROUP(edge_rpc) {
    void setup() {
        rpc_init();
        rpc_set_generate_msg_id(test_generate_msg_id);
    }

    void teardown() {
        rpc_destroy_messages();
        reset_counter();
        rpc_deinit();
    }
};

static void generic_response_callback(json_t *response, void *userdata)
{
    mock().actualCall("callback");
    json_object_set_new(response, "id", json_string("100"));
}

static void generic_sleeping_response_callback(json_t *response, void *userdata)
{
    mock().actualCall("callback");
    // sleep for 1000 ms, tests the callback timing warning.
    struct timespec tim, tim2;
    tim.tv_sec = 0;
    tim.tv_nsec = 6e+8;
    nanosleep(&tim, &tim2);
}

TEST(edge_rpc, test_rpc_handle_message_not_found)
{
    bool protocol_error;
    struct connection *connection = (struct connection *) calloc(1, sizeof(struct connection));
    json_t *response_obj = json_object();
    json_object_set_new(response_obj, "id", json_string("not-to-be-found"));

    // response gets freed in the message handling
    char *response = json_dumps(response_obj, JSON_COMPACT);
    int rc = rpc_handle_message(response,
                                strlen(response),
                                connection,
                                method_table,
                                NULL,
                                &protocol_error,
                                false /* mutex_acquired */);
    CHECK_EQUAL(1, rc);
    CHECK_EQUAL(false, protocol_error);
    free(response);
    json_decref(response_obj);
    free(connection);
};

void generic_free_func(rpc_request_context_t *userdata)
{
    (void) userdata;
    mock().actualCall("freefunc");
}

static void send_test_request(struct connection *connection,
                              rpc_response_handler response_callback,
                              json_t **json_request,
                              char **request,
                              char **expected_response,
                              json_t **result_obj,
                              JsonPointer **result_obj_p,
                              JsonMessageTPointer **userdata,
                              char **message_id)
{
    bool protocol_error;
    void *message_entry;
    json_t *request_obj = allocate_base_request("test");
    size_t request_len;
    rpc_request_context_t context;
    memset(&context, 0, sizeof(rpc_request_context_t));
    int rc = rpc_construct_message(request_obj,
                                   response_callback,
                                   response_callback,
                                   generic_free_func,
                                   &context,
                                   connection,
                                   &message_entry,
                                   request,
                                   &request_len,
                                   message_id);
    CHECK_EQUAL(0, rc);

    rpc_add_message_entry_to_list(message_entry);
    *result_obj = json_object();
    json_object_set_new(*result_obj, "test-result", json_string("good"));

    json_t *empty_obj = json_object();
    JsonPointer expected_params = JsonPointer(empty_obj);
    *result_obj_p = new JsonPointer(*result_obj);
    *userdata = new JsonMessageTPointer(*request, request_len, connection);

    *json_request = json_object();
    JsonPointer expected_request = JsonPointer(*json_request);
    json_object_set_new(*json_request, "id", json_string("1"));
    json_object_set_new(*json_request, "jsonrpc", json_string("2.0"));
    json_object_set_new(*json_request, "method", json_string("test"));
    json_object_set_new(*json_request, "params", json_object());

    mock().expectOneCall("rpc_test_handler")
            .withParameterOfType("JsonPointer", "json_request", &expected_request)
            .withParameterOfType("JsonPointer", "json_params", &expected_params)
            .withOutputParameterOfTypeReturning("JsonPointer", "result", *result_obj_p)
            .withParameterOfType("JsonMessageTPointer", "userdata", *userdata);

    *expected_response = strdup("{\"id\":\"1\",\"jsonrpc\":\"2.0\",\"result\":{\"test-result\":\"good\"}}");

    mock().expectOneCall("write_func")
            .withPointerParameter("connection", connection)
            .withParameter("data", *expected_response)
            .withParameter("size", strlen(*expected_response));

    mock().expectOneCall("freefunc");

    rc = rpc_handle_message(*request,
                            request_len,
                            connection,
                            method_table,
                            rpc_write_func_mock,
                            &protocol_error,
                            false /* mutex_acquired */);
    CHECK_EQUAL(0, rc);
    CHECK_EQUAL(false, protocol_error);
    CHECK_EQUAL(1, rpc_message_list_size());
    json_decref(empty_obj);
}

void test_rpc_handle_message_callback(bool sleep, bool wrong_connection)
{
    bool protocol_error;
    int rc;
    char *expected_response;
    json_t *result_obj;
    struct connection *connection = (struct connection *) calloc(1, sizeof(struct connection));
    struct connection *connection2 = (struct connection *) calloc(1, sizeof(struct connection));
    char *message_id;
    char *request;
    json_t *json_request;
    JsonPointer *result_obj_p;
    JsonMessageTPointer *userdata;
    rpc_response_handler response_callback = generic_response_callback;
    if (sleep) {
        response_callback = generic_sleeping_response_callback;
    }

    send_test_request(connection,
                      response_callback,
                      &json_request,
                      &request,
                      &expected_response,
                      &result_obj,
                      &result_obj_p,
                      &userdata,
                      &message_id);

    if (!wrong_connection) {
        mock().expectOneCall("callback");
        rc = rpc_handle_message(expected_response,
                                strlen(expected_response),
                                connection,
                                method_table,
                                NULL,
                                &protocol_error,
                                false /* mutex_acquired */);
    } else {
        rc = rpc_handle_message(expected_response,
                                strlen(expected_response),
                                connection2, /* This is a different connection! */
                                method_table,
                                NULL,
                                &protocol_error,
                                false /* mutex_acquired */);
        rpc_destroy_messages();
    }
    if (wrong_connection) {
        CHECK_EQUAL(1, rc);
        CHECK_EQUAL(true, protocol_error);
    } else {
        CHECK_EQUAL(0, rc);
        CHECK_EQUAL(false, protocol_error);
    }
    CHECK(rpc_message_list_is_empty());

    mock().checkExpectations();
    json_decref(result_obj);
    json_decref(json_request);
    free(expected_response);
    free(request);
    free(message_id);
    free(connection);
    free(connection2);
    delete userdata;
    delete result_obj_p;
}

TEST(edge_rpc, test_rpc_handle_message_callback_without_sleep)
{
    test_rpc_handle_message_callback(false /* sleep */, false /* wrong_connection */);
}

TEST(edge_rpc, test_rpc_handle_message_callback_with_sleep)
{
    test_rpc_handle_message_callback(true /* sleep */, false /* wrong_connection */);
}

TEST(edge_rpc, test_rpc_handle_message_callback_with_wrong_response_connection)
{
    test_rpc_handle_message_callback(true /* sleep */, true /* wrong_connection */);
}

void test_rpc_handle_message_callback_error_response()
{
    bool protocol_error;
    struct connection *connection = (struct connection *) calloc(1, sizeof(struct connection));
    json_t *request_obj = allocate_base_request("test-error");
    void *message_entry;
    char *request;
    size_t request_len;
    char *message_id;
    rpc_request_context_t context;
    memset(&context, 0, sizeof(rpc_request_context_t));
    int rc = rpc_construct_message(request_obj,
                                   generic_response_callback,
                                   generic_response_callback,
                                   generic_free_func,
                                   &context,
                                   connection,
                                   &message_entry,
                                   &request,
                                   &request_len,
                                   &message_id);

    CHECK_EQUAL(0, rc);
    rpc_add_message_entry_to_list(message_entry);
    json_t *error_obj = json_object();
    json_object_set_new(error_obj, "code", json_integer(-100));
    json_object_set_new(error_obj, "message", json_string("test-error"));

    json_t *empty_obj = json_object();
    json_t *json_request = json_object();
    JsonPointer expected_request = JsonPointer(json_request);
    JsonPointer expected_params = JsonPointer(empty_obj);
    JsonPointer error_obj_p = JsonPointer(error_obj);
    JsonMessageTPointer userdata = JsonMessageTPointer(request, request_len, connection);
    // {"id":"1","jsonrpc":"2.0","method":"test-error","params":{}
    json_object_set_new(json_request, "id", json_string("1"));
    json_object_set_new(json_request, "jsonrpc", json_string("2.0"));
    json_object_set_new(json_request, "method", json_string("test-error"));
    json_object_set_new(json_request, "params", json_object());
    mock().expectOneCall("rpc_test_handler")
            .withParameterOfType("JsonPointer", "json_request", &expected_request)
            .withParameterOfType("JsonPointer", "json_params", &expected_params)
            .withOutputParameterOfTypeReturning("JsonPointer", "result", &error_obj_p)
            .withParameterOfType("JsonMessageTPointer", "userdata", &userdata);

    char *expected_response = strdup("{\"error\":{\"code\":-100,\"message\":\"test-error\"},\"id\":\"1\",\"jsonrpc\":\"2.0\"}");

    mock().expectOneCall("write_func")
            .withPointerParameter("connection", connection)
            .withParameter("data", expected_response)
            .withParameter("size", strlen(expected_response));

    mock().expectOneCall("callback");
    mock().expectOneCall("freefunc");

    rc = rpc_handle_message(request,
                            request_len,
                            connection,
                            method_table,
                            rpc_write_func_mock,
                            &protocol_error,
                            false /* mutex_acquired */);
    CHECK_EQUAL(0, rc);
    CHECK_EQUAL(false, protocol_error);
    CHECK_EQUAL(1, rpc_message_list_size());

    rc = rpc_handle_message(expected_response,
                            strlen(expected_response),
                            connection,
                            method_table,
                            NULL,
                            &protocol_error,
                            false /* mutex_acquired */);
    CHECK_EQUAL(0, rc);
    CHECK_EQUAL(false, protocol_error);
    CHECK(rpc_message_list_is_empty());
    json_decref(json_request);
    json_decref(error_obj);
    json_decref(empty_obj);
    free(expected_response);
    free(request);
    free(message_id);
    free(connection);
    mock().checkExpectations();
}

TEST(edge_rpc, test_rpc_handle_message_callback_with_error_response)
{
    test_rpc_handle_message_callback_error_response();
}

TEST(edge_rpc, test_rpc_handle_response_no_request_id_obj)
{
    char *response = strdup("{\"jsonrpc\":\"2.0\",\"result\":\"no-id-obj\"}");
    bool protocol_error;
    struct connection *connection = (struct connection *) calloc(1, sizeof(struct connection));
    int rc = rpc_handle_message(response,
                                strlen(response),
                                connection,
                                method_table,
                                rpc_write_func_mock,
                                &protocol_error,
                                false /* mutex_acquired */);
    CHECK_EQUAL(1, rc);
    CHECK_EQUAL(false, protocol_error);
    free(response);
    free(connection);
    mock().checkExpectations();
}

TEST(edge_rpc, test_rpc_handle_response_request_id_obj_content_empty)
{
    char *response = strdup("{\"id\":\"\",\"jsonrpc\":\"2.0\",\"result\":\"no-id-obj\"}");
    struct connection *connection = (struct connection *) calloc(1, sizeof(struct connection));
    bool protocol_error;
    int rc = rpc_handle_message(response,
                                strlen(response),
                                connection,
                                method_table,
                                rpc_write_func_mock,
                                &protocol_error,
                                false /* mutex_acquired */);
    CHECK_EQUAL(1, rc);
    CHECK_EQUAL(true, protocol_error);
    free(response);
    free(connection);
    mock().checkExpectations();
}

TEST(edge_rpc, test_rpc_handle_response_method_table_obj_content_empty)
{
    struct connection *connection = (struct connection *) calloc(1, sizeof(struct connection));
    char *response = strdup("{\"id\":\"1\",\"jsonrpc\":\"2.0\",\"result\":\"no-id-obj\"}");
    bool protocol_error;
    int rc = rpc_handle_message(response,
                                strlen(response),
                                connection,
                                NULL,
                                rpc_write_func_mock,
                                &protocol_error,
                                false /* mutex_acquired */);
    CHECK_EQUAL(1, rc);
    CHECK_EQUAL(true, protocol_error);
    free(response);
    free(connection);
    mock().checkExpectations();
}

TEST(edge_rpc, test_rpc_construct_message_null_message)
{
    void *message_entry = NULL;
    char *data;
    size_t data_len;
    char *message_id;
    struct connection dummy_connection;
    memset(&dummy_connection, 0, sizeof(struct connection));
    CHECK_EQUAL(1,
                rpc_construct_message(NULL,
                                      NULL,
                                      NULL,
                                      NULL,
                                      NULL,
                                      &dummy_connection,
                                      &message_entry,
                                      &data,
                                      &data_len,
                                      &message_id));
    CHECK(message_entry == NULL);
    mock().checkExpectations();
}

TEST(edge_rpc, test_rpc_construct_message_null_data)
{
    void *message_entry;
    json_t *msg = json_object();
    json_object_set_new(msg, "msg-content", json_string("content"));
    char *message_id;
    struct connection dummy_connection;
    memset(&dummy_connection, 0, sizeof(struct connection));
    CHECK_EQUAL(1,
                rpc_construct_message(msg,
                                      NULL,
                                      NULL,
                                      NULL,
                                      NULL,
                                      &dummy_connection,
                                      &message_entry,
                                      NULL,
                                      0,
                                      &message_id));
    CHECK(message_entry == NULL);
    json_decref(msg);
    mock().checkExpectations();
}

TEST(edge_rpc, test_rpc_construct_message_null_message_id)
{
    void *message_entry;
    json_t *msg = json_object();
    json_object_set_new(msg, "msg-content", json_string("content"));
    char *data;
    size_t data_len;
    struct connection dummy_connection;
    memset(&dummy_connection, 0, sizeof(struct connection));
    CHECK_EQUAL(1,
                rpc_construct_message(msg,
                                      NULL,
                                      NULL,
                                      NULL,
                                      NULL,
                                      &dummy_connection,
                                      &message_entry,
                                      &data,
                                      &data_len,
                                      NULL));
    CHECK(message_entry == NULL);
    json_decref(msg);
    mock().checkExpectations();
}

TEST(edge_rpc, test_rpc_construct_message)
{
    void *message_entry;
    json_t *msg = json_object();
    json_object_set_new(msg, "msg-content", json_string("content"));
    char *data;
    size_t data_len;
    char *message_id;
    rpc_request_context_t context;
    struct connection dummy_connection;
    memset(&dummy_connection, 0, sizeof(struct connection));
    memset(&context, 0, sizeof(rpc_request_context_t));
    CHECK_EQUAL(0,
                rpc_construct_message(msg,
                                      NULL,
                                      NULL,
                                      NULL,
                                      &context,
                                      &dummy_connection,
                                      &message_entry,
                                      &data,
                                      &data_len,
                                      &message_id));
    rpc_add_message_entry_to_list(message_entry);
    STRNCMP_EQUAL("{\"id\":\"1\",\"msg-content\":\"content\"}", data, data_len);
    CHECK_EQUAL(1, rpc_message_list_size());
    free(data);
    free(message_id);
    mock().checkExpectations();
}

TEST(edge_rpc, test_rpc_construct_response_null_response)
{
    CHECK_EQUAL(1, rpc_construct_response(NULL, NULL, NULL));
    mock().checkExpectations();
}

TEST(edge_rpc, test_rpc_construct_response_null_data)
{
    json_t *response = json_object();
    CHECK_EQUAL(1, rpc_construct_response(response, NULL, NULL));
    json_decref(response);
    mock().checkExpectations();
}

TEST(edge_rpc, test_rpc_construct_response_null_data_len)
{
    json_t *response = json_object();
    char *data = NULL;
    CHECK_EQUAL(1, rpc_construct_response(response, &data, NULL));
    json_decref(response);
    mock().checkExpectations();
}

TEST(edge_rpc, test_rpc_construct_response_valid_params)
{
    json_t *response = json_object();
    json_object_set_new(response, "id", json_string("934"));
    char *data = NULL;
    size_t data_len = 0;
    CHECK_EQUAL(0, rpc_construct_response(response, &data, &data_len));
    // check updates data_len
    CHECK_EQUAL(12, data_len);
    free(data);
    json_decref(response);
    mock().checkExpectations();
}

TEST(edge_rpc, test_invalid_jsonrpc_method)
{
    bool protocol_error;
    struct connection *connection = (struct connection *) calloc(1, sizeof(struct connection));
    json_t *request_obj = allocate_base_request("invalid-method");
    json_object_set_new(request_obj, "id", json_string("1"));
    char* request = json_dumps(request_obj, JSON_COMPACT | JSON_SORT_KEYS);

    const char *expected_response = "{\"error\":{\"code\":-32601,\"message\":\"Method not found\"},\"id\":\"1\",\"jsonrpc\":\"2.0\"}";

    mock().expectOneCall("write_func")
            .withPointerParameter("connection", connection)
            .withParameter("data", expected_response)
            .withParameter("size", strlen(expected_response));

    int rc = rpc_handle_message(request,
                                strlen(request),
                                connection,
                                method_table,
                                rpc_write_func_mock,
                                &protocol_error,
                                false /* mutex_acquired */);
    CHECK_EQUAL(0, rc);
    CHECK_EQUAL(false, protocol_error);
    CHECK_EQUAL(0, rpc_message_list_size());
    free(request);
    json_decref(request_obj);
    free(connection);
    mock().checkExpectations();
}

TEST(edge_rpc, test_invalid_jsonrpc_notification)
{
    bool protocol_error;
    json_t *request_obj = allocate_base_request("invalid-method");
    char* request = json_dumps(request_obj, JSON_COMPACT | JSON_SORT_KEYS);
    struct connection *connection = (struct connection *) calloc(1, sizeof(struct connection));

    int rc = rpc_handle_message(request,
                                strlen(request),
                                connection,
                                method_table,
                                rpc_write_func_mock,
                                &protocol_error,
                                false /* mutex_acquired */);
    CHECK_EQUAL(1, rc);
    CHECK_EQUAL(false, protocol_error);
    CHECK_EQUAL(0, rpc_message_list_size());
    free(request);
    json_decref(request_obj);
    free(connection);
    mock().checkExpectations();
}

TEST(edge_rpc, test_invalid_json)
{
    bool protocol_error;
    const char *req = "{\"method\":\"unknown\",\"id\":\"2\",\"params\":{},\"jsonrpc\":\"2.0\"}";
    // simulate protocol getting out of sync
    char *request = strndup(req + 3, 100);
    struct connection *connection = (struct connection *) calloc(1, sizeof(struct connection));

    int rc = rpc_handle_message(request,
                                strlen(request),
                                connection,
                                method_table,
                                rpc_write_func_mock,
                                &protocol_error,
                                false /* mutex_acquired */);
    CHECK_EQUAL(1, rc);
    CHECK_EQUAL(true, protocol_error);
    CHECK_EQUAL(0, rpc_message_list_size());
    free(connection);
    free(request);
    mock().checkExpectations();
}

TEST(edge_rpc, test_construct_and_send_response_with_response_null)
{
    struct connection *connection = NULL;
    json_t *response = NULL;
    CHECK(-1 == rpc_construct_and_send_response(connection, response, NULL, NULL, NULL));
    mock().checkExpectations();
}

static void checked_response_callback(json_t *response, void *userdata)
{
    char *response_str = json_dumps(response, JSON_COMPACT | JSON_SORT_KEYS);
    mock().actualCall("checked_response_callback").withStringParameter("response", response_str);
    free(response_str);
}

TEST(edge_rpc, test_remote_disconnected_with_connection_and_pending_message)
{
    struct connection *connection = (struct connection *) calloc(1, sizeof(struct connection));
    char *expected_response;
    json_t *result_obj;
    char *message_id;
    char *request;
    json_t *json_request;
    JsonPointer *result_obj_p;
    JsonMessageTPointer *userdata;

    send_test_request(connection,
                      checked_response_callback,
                      &json_request,
                      &request,
                      &expected_response,
                      &result_obj,
                      &result_obj_p,
                      &userdata,
                      &message_id);

    mock().expectOneCall("checked_response_callback")
            .withStringParameter("response",
                                 "{\"error\":{\"code\":-30008,\"data\":\"Remote disconnected\",\"message\":\"Remote "
                                 "disconnected.\"},\"id\":\"1\",\"jsonrpc\":\"2.0\"}");
    rpc_remote_disconnected(connection);
    mock().checkExpectations();
    json_decref(result_obj);
    json_decref(json_request);
    free(expected_response);
    free(request);
    free(message_id);
    free(connection);
    delete userdata;
    delete result_obj_p;
}

TEST(edge_rpc, test_timeout_pending_messages_with_connection_and_pending_message)
{
    struct connection *connection = (struct connection *) calloc(1, sizeof(struct connection));
    char *expected_response;
    json_t *result_obj;
    char *message_id;
    char *request;
    json_t *json_request;
    JsonPointer *result_obj_p;
    JsonMessageTPointer *userdata;

    send_test_request(connection,
                      checked_response_callback,
                      &json_request,
                      &request,
                      &expected_response,
                      &result_obj,
                      &result_obj_p,
                      &userdata,
                      &message_id);

    struct timespec tim, tim2;
    tim.tv_sec = 0;
    tim.tv_nsec = 6e+7;
    nanosleep(&tim, &tim2);
    mock().expectOneCall("checked_response_callback")
            .withStringParameter("response",
                                 "{\"error\":{\"code\":-30007,\"data\":\"Timeout response with timeout threshold 1 "
                                 "ms\",\"message\":\"Request timeout.\"},\"id\":\"1\",\"jsonrpc\":\"2.0\"}");
    rpc_timeout_unresponded_messages(1);
    mock().checkExpectations();
    json_decref(result_obj);
    json_decref(json_request);
    free(expected_response);
    free(request);
    free(message_id);
    free(connection);
    delete userdata;
    delete result_obj_p;
}

TEST(edge_rpc, test_rpc_timeout_api)
{
    struct event_base *base = evbase_mock_new();
    struct event *event = (struct event *) calloc(1, sizeof(struct event));
    event->base = base;
    mock().expectOneCall("event_new")
            .withPointerParameter("base", base)
            .withIntParameter("fd", -1)
            .withIntParameter("flags", EV_PERSIST)
            .withPointerParameter("callback_fn", (void *) handle_timed_out_requests)
            .andReturnValue(event);
    mock().expectOneCall("event_add").andReturnValue(0);

    rpc_request_timeout_hander_t *handler = rpc_request_timeout_api_start(base, 1000, 2000);
    handle_timed_out_requests(-1, 0, handler);
    mock().expectOneCall("event_del").withPointerParameter("ev", event).andReturnValue(0);
    mock().expectOneCall("event_free").withPointerParameter("ev", event);
    rpc_request_timeout_api_stop(handler);
    evbase_mock_delete(base);
    free(event);
}

TEST(edge_rpc, test_rpc_timeout_api_event_new_fails)
{
    struct event_base *base = evbase_mock_new();
    mock().expectOneCall("event_new")
            .withPointerParameter("base", base)
            .withIntParameter("fd", -1)
            .withIntParameter("flags", EV_PERSIST)
            .withPointerParameter("callback_fn", (void *) handle_timed_out_requests)
            .andReturnValue((void *) NULL);
    rpc_request_timeout_hander_t *handler = rpc_request_timeout_api_start(base, 1000, 2000);
    CHECK_EQUAL((void *) NULL, handler);
    evbase_mock_delete(base);
}

TEST(edge_rpc, test_rpc_timeout_api_event_add_fails)
{
    struct event_base *base = evbase_mock_new();
    struct event *event = (struct event *) calloc(1, sizeof(struct event));
    event->base = base;
    mock().expectOneCall("event_new")
            .withPointerParameter("base", base)
            .withIntParameter("fd", -1)
            .withIntParameter("flags", EV_PERSIST)
            .withPointerParameter("callback_fn", (void *) handle_timed_out_requests)
            .andReturnValue(event);
    mock().expectOneCall("event_add").andReturnValue(-1);
    mock().expectOneCall("event_free").withPointerParameter("ev", event);
    rpc_request_timeout_hander_t *handler = rpc_request_timeout_api_start(base, 1000, 2000);
    CHECK_EQUAL((void *) NULL, handler);
    evbase_mock_delete(base);
    free(event);
}

TEST(edge_rpc, test_rpc_timeout_api_stop_fails)
{
    struct event_base *base = evbase_mock_new();
    struct event *event = (struct event *) calloc(1, sizeof(struct event));
    event->base = base;
    mock().expectOneCall("event_new")
            .withPointerParameter("base", base)
            .withIntParameter("fd", -1)
            .withIntParameter("flags", EV_PERSIST)
            .withPointerParameter("callback_fn", (void *) handle_timed_out_requests)
            .andReturnValue(event);
    mock().expectOneCall("event_add").andReturnValue(0);

    rpc_request_timeout_hander_t *handler = rpc_request_timeout_api_start(base, 1000, 2000);
    handle_timed_out_requests(-1, 0, handler);
    mock().expectOneCall("event_del").withPointerParameter("ev", event).andReturnValue(-1);
    mock().expectOneCall("event_free").withPointerParameter("ev", event);
    rpc_request_timeout_api_stop(handler);
    evbase_mock_delete(base);
    free(event);
}

