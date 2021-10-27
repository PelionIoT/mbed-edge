#include "edge-rpc/rpc.h"
#include "client_type.h"
#include "edge-core/server.h"

int sda_request(json_t *request, json_t *json_params, json_t **result, void *userdata);
extern struct jsonrpc_method_entry_t sda_method_table[];
