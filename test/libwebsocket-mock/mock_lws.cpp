#include "CppUTest/TestHarness.h"
#include "CppUTestExt/MockSupport.h"
extern "C" {
#include "common/websocket_comm.h"
#include "libwebsockets.h"
#include "libwebsocket-mock/lws_mock.h"
#include <assert.h>
#include "cpputest-custom-types/my_json_frame.h"
#include "edge-core/websocket_serv.h"
#define TRACE_GROUP "lws_mock"
#include "mbed-trace/mbed_trace.h"

static struct lws_context *context = NULL;
static struct lws *current_wsi = NULL;
bool expect_connection_failure = false;

struct lws_context *lws_mock_get_context()
{
    return context;
}

struct lws *lws_mock_get_wsi()
{
    return current_wsi;
}

static struct lws *init_wsi_common()
{
    struct lws *wsi = (struct lws *) calloc(1, sizeof(struct lws));
    wsi->context = context;
    wsi->protocol = &context->protocols[0];
    current_wsi = wsi;
    return wsi;
}

struct lws *lws_mock_create_wsi()
{
    struct lws *wsi = init_wsi_common();
    wsi->userdata = calloc(1, context->protocols[0].per_session_data_size);
    return wsi;
}

struct lws *lws_mock_create_wsi_with_userdata(void *userdata)
{
    struct lws *wsi = init_wsi_common();
    assert(userdata != NULL);
    wsi->userdata = userdata;
    wsi->is_client = true;
    return wsi;
}

int lws_mock_callback(struct lws *wsi, enum lws_callback_reasons reason)
{
    return wsi->protocol->callback(wsi, reason, wsi->userdata, NULL, 0);
}

void lws_mock_destroy_wsi(struct lws *wsi)
{
    current_wsi = NULL;
    if (!wsi->is_client) {
        free(wsi->userdata);
    }
    free(wsi);
}

void *lws_wsi_user(struct lws *wsi)
{
    return mock()
        .actualCall("lws_wsi_user")
        .returnPointerValue();
}

void lws_close_reason(struct lws *wsi, enum lws_close_status status,
		 unsigned char *buf, size_t len)
{
    mock().actualCall("lws_close_reason");
}

void lws_set_log_level(int level, void (*func)(int level, const char *line))
{
    mock().actualCall("lws_set_log_level");
}

int lws_write(struct lws *wsi, unsigned char *buf, size_t len,
              enum lws_write_protocol protocol)
{
    MyJsonFrame *frame = new MyJsonFrame((const char *) buf, len);
    int ret_val = mock().actualCall("lws_write")
                          .withParameterOfType("MyJsonFrame", "buf", (const void *) frame)
                          .returnIntValue();
    delete frame;
    return ret_val;
}

void lws_mock_callback_client_receive(unsigned char *buf, size_t len, int expected_ret_val)
{
    // connection must exist
    assert(current_wsi);
    struct lws *wsi = current_wsi;
    int ret_val = wsi->protocol->callback(wsi, LWS_CALLBACK_CLIENT_RECEIVE, wsi->userdata, buf, len);
    CHECK(expected_ret_val == ret_val);
}

int lws_callback_on_writable(struct lws *wsi)
{
    int expected_val = mock().actualCall("lws_callback_on_writable").returnIntValue();
    // There are some tests which don't establish connection. Therefore make callback only if
    // connection is established.
    if (wsi) {
        enum lws_callback_reasons reason = LWS_CALLBACK_SERVER_WRITEABLE;
        if (wsi->is_client) {
            reason = LWS_CALLBACK_CLIENT_WRITEABLE;
        }
        (void) wsi->protocol->callback(wsi, reason, wsi->userdata, NULL, 0);
    }
    return expected_val;
}

void lws_mock_call_receive_cb(struct lws *wsi, void *in, size_t len)
{
    wsi->protocol->callback(wsi, LWS_CALLBACK_RECEIVE, wsi->userdata, in, len);
}

int lws_callback_on_writable_all_protocol(const struct lws_context *context,
                                          const struct lws_protocols *protocol)
{
    return mock()
        .actualCall("lws_callback_on_writable_all_protocol")
        .returnIntValue();
}

struct lws_context *lws_create_context(const struct lws_context_creation_info *info)
{
    assert(NULL == context);
    struct lws_context *ctx = (struct lws_context *) calloc(1, sizeof(struct lws_context));
    context = ctx;
    ctx->protocols = info->protocols;

    mock().actualCall("lws_create_context");
    return ctx;
}

int lws_event_initloop(struct lws_context *context, struct event_base *loop,
		  int tsi)
{
    return mock()
        .actualCall("lws_event_initloop")
        .returnIntValue();
}

void lws_context_destroy(struct lws_context *ctx)
{
    context = NULL;
    // This is a bit ugly, because I'm not sure what the libwebsocket does when libevent dispatch loop fails
    // and client's connection is not ever really created.
    if (current_wsi) {
        if (!current_wsi->connection_established) {
            lws_mock_destroy_wsi(current_wsi);
        }
    }

    free(ctx);
    mock().actualCall("lws_context_destroy");
}

const struct lws_protocols *lws_get_protocol(struct lws *wsi)
{
    lws_protocols* protocols = (lws_protocols*) mock().
        actualCall("lws_get_protocol")
        .returnPointerValue();
    return protocols;
}

int lws_http_client_read(struct lws *wsi, char **buf, int *len)
{
    return mock().actualCall("lws_http_client_read").returnIntValue();
}

unsigned int lws_http_client_http_response(struct lws *wsi)
{
    return mock().actualCall("lws_http_client_http_response").returnUnsignedIntValue();
}

LWS_VISIBLE LWS_EXTERN struct lws *lws_client_connect_via_info(const struct lws_client_connect_info * ccinfo)
{
    mock().actualCall("lws_client_connect_via_info").withStringParameter("path", ccinfo->path);
    struct lws *lws = (struct lws *) lws_mock_create_wsi_with_userdata(ccinfo->userdata);
    lws->context = ccinfo->context;
    lws->protocol = &ccinfo->context->protocols[0];
    if (expect_connection_failure) {
        lws_mock_callback(lws, LWS_CALLBACK_CLIENT_CONNECTION_ERROR);
        lws_mock_callback(lws, LWS_CALLBACK_WSI_DESTROY);
        lws_mock_destroy_wsi(lws);
        lws = NULL;
        expect_connection_failure = false;
     }
     return lws;
}

int lws_extension_callback_pm_deflate(
	struct lws_context *context, const struct lws_extension *ext,
	struct lws *wsi, enum lws_extension_callback_reasons reason,
	void *user, void *in, size_t len)
{
    return mock().
        actualCall("lws_extension_callback_pm_deflate")
        .returnIntValue();
}

void lws_mock_connection_established(struct lws *wsi, enum lws_callback_reasons reason)
{
    wsi->connection_established = true;
    wsi->protocol->callback(wsi, reason, wsi->userdata, NULL, 0);
}

void lws_mock_connection_closed(struct lws *wsi)
{
    wsi->protocol->callback(wsi, LWS_CALLBACK_CLOSED, wsi->userdata, NULL, 0);
    lws_mock_destroy_wsi(wsi);
}

void lws_mock_setup_connection_failure()
{
    expect_connection_failure = true;
}

int lws_hdr_total_length(struct lws *wsi, enum lws_token_indexes h)
{
    return mock().actualCall("lws_hdr_total_length")
        .withIntParameter("h", h)
        .returnIntValue();
}

int lws_hdr_copy(struct lws *wsi, char *dest, int len, enum lws_token_indexes h)
{
    return mock()
            .actualCall("lws_hdr_copy")
            .withIntParameter("len", len)
            .withOutputParameter("dest", dest)
            .withIntParameter("h", h)
            .returnIntValue();
}

size_t lws_remaining_packet_payload(struct lws *wsi)
{
    return mock()
        .actualCall("lws_remaining_packet_payload")
        .returnIntValue();
}

int lws_is_final_fragment(struct lws *wsi)
{
    return mock()
        .actualCall("lws_is_final_fragment")
        .returnIntValue();
}

int lws_is_first_fragment(struct lws *wsi)
{
    return mock()
        .actualCall("lws_is_first_fragment")
        .returnIntValue();
}
} /* extern "C" */
