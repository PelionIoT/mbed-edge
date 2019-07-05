#include "common/pt_api_error_parser.h"
#include "common/pt_api_error_codes.h"
#include "mbed-trace/mbed_trace.h"
#define TRACE_GROUP "jsonrpcerror"

void pt_api_error_parser_parse_error_response(json_t *response, edgeclient_request_context_t *ctx)
{
    int32_t code = PT_API_INTERNAL_ERROR;
    json_t *error = json_object_get(response, "error");
    json_t *id_obj = json_object_get(response, "id");
    char *id = NULL;

    if (id_obj) {
        id = json_dumps(id_obj, JSON_COMPACT|JSON_ENCODE_ANY);
    }

    if (error) {
        json_t *code_obj = json_object_get(error, "code");
        if (code_obj) {
            code = json_integer_value(code_obj);
        } else {
            tr_err("pt_api_error_parser_parse_error_response: missing error code for response, id: %s", id);
        }
    } else {
        tr_err("pt_api_error_parser_parse_error_response: missing error object for response, id: %s", id);
    }
    free(id);
    ctx->jsonrpc_error_code = code;
}

