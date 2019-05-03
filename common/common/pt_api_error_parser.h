
#include "edge-client/request_context.h"
#include "jansson.h"

/**
 * \brief Parses the error code from the JSONRPC error response.
 * \param response The JSONRPC error response. `response` may not be NULL.
 * \param ctx Pointer to Edge Client request context. The value is written to `ctx->json`. `ctx` may not be NULL.
 */
void pt_api_error_parser_parse_error_response(json_t *response, edgeclient_request_context_t *ctx);

