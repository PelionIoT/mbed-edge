#ifndef TEST_TEST_LIB_TEST_LIB_RPC_MOCKS_H_
#define TEST_TEST_LIB_TEST_LIB_RPC_MOCKS_H_

#include <stdlib.h>
#include <jansson.h>

int rpc_write_func_mock(struct connection *connection, char *data, size_t size);
int rpc_test_handler_success(json_t *request, json_t *params, json_t **result, void *userdata);
int rpc_test_handler_error(json_t *request, json_t *params, json_t **result, void *userdata);

#endif // TEST_TEST_LIB_TEST_LIB_RPC_MOCKS_H_
