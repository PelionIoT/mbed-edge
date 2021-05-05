#include "CppUTestExt/MockSupport.h"
#include "cpputest-custom-types/value_pointer.h"
extern "C" {
#include "libwebsockets.h"
}

int lws_callback_on_writable(struct lws *wsi)
{
    return mock().actualCall("lws_callback_on_writable")
        .returnIntValueOrDefault(0);
}

size_t lws_remaining_packet_payload(struct lws *wsi)
{
    return mock().actualCall("lws_remaining_packet_payload").returnUnsignedLongIntValue();
}

int lws_is_final_fragment(struct lws *wsi)
{
    return mock().actualCall("lws_is_final_fragment").returnIntValue();
}

int lws_is_first_fragment(struct lws *wsi)
{
    return mock().actualCall("lws_is_first_fragment").returnIntValue();
}

void lws_close_reason(struct lws *wsi, enum lws_close_status status, unsigned char *buf, size_t len)
{
    mock().actualCall("lws_close_reason");
}

int lws_write(struct lws *wsi, unsigned char *buf, size_t len, enum lws_write_protocol protocol)
{
    ValuePointer msg_param = ValuePointer(buf, len);
    return mock().actualCall("lws_write")
        .withParameterOfType("ValuePointer", "buf", &msg_param)
        .returnIntValue();
}

struct lws_context *lws_create_context(const struct lws_context_creation_info *info)
{
    return (struct lws_context*) mock().actualCall("lws_create_context").returnPointerValue();
}

void lws_context_destroy(struct lws_context *ctx)
{
    mock().actualCall("lws_context_destroy");
    free(ctx);
}

LWS_VISIBLE LWS_EXTERN struct lws *lws_client_connect_via_info(const struct lws_client_connect_info *ccinfo)
{
    return (struct lws*) mock().actualCall("lws_client_connect_via_info")
        .withStringParameter("path", ccinfo->path)
        .returnPointerValue();
}

int lws_extension_callback_pm_deflate(struct lws_context *context,
                                      const struct lws_extension *ext,
                                      struct lws *wsi,
                                      enum lws_extension_callback_reasons reason,
                                      void *user,
                                      void *in,
                                      size_t len)
{
    return mock().actualCall("lws_extension_callback_pm_deflate").returnIntValue();
}
