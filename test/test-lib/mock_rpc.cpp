#include "CppUTestExt/MockSupport.h"
#include "test-lib/rpc_mocks.h"
#include "test-lib/json_pointer.h"
#include "test-lib/json_message_t_pointer.h"

int rpc_write_func_mock(struct connection *connection, char *data, size_t size)
{
    mock().actualCall("write_func")
        .withParameter("connection", connection)
        .withParameter("data", data)
        .withParameter("size", size);
    // This mocks the data writing to ouput socket
    // must free the data here.
    free(data);
    return 0;
}

void rpc_test_handler(json_t *request, json_t *params, json_t *result, void *userdata)
{
    JsonPointer request_p = JsonPointer(request);
    JsonPointer params_p = JsonPointer(params);
    JsonPointer result_p = JsonPointer(result);

    json_message_t *userdata_s = (json_message_t*) userdata;
    JsonMessageTPointer userdata_p = JsonMessageTPointer(userdata_s->data,
                                                         userdata_s->len,
                                                         userdata_s->connection);

    mock().actualCall("rpc_test_handler")
            .withParameterOfType("JsonPointer", "json_request", &request_p)
            .withParameterOfType("JsonPointer", "json_params", &params_p)
            .withOutputParameterOfType("JsonPointer", "result", &result_p)
            .withParameterOfType("JsonMessageTPointer", "userdata", &userdata_p);
}

int rpc_test_handler_success(json_t *request, json_t *params, json_t **result, void *userdata)
{
    *result = json_object();
    json_object_set_new(*result, "test-result", json_string("good"));
    rpc_test_handler(request, params, *result, userdata);
    return 0;
}

int rpc_test_handler_error(json_t *request, json_t *params, json_t **result, void *userdata)
{
    *result = json_object();
    json_object_set_new(*result, "code", json_integer(-100));
    json_object_set_new(*result, "message", json_string("test-error"));
    rpc_test_handler(request, params, *result, userdata);
    return 1;
}
