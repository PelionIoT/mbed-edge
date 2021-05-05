#ifndef LWS_MOCK_H
#define LWS_MOCK_H

#include <stddef.h>
#include "libwebsockets.h"

struct lws_context {
    const struct lws_protocols *protocols;
};

struct lws {
    struct lws_context *context;
    void *userdata;
    const struct lws_protocols *protocol;
    bool is_client;
    bool connection_established;
};

struct lws_context *lws_mock_get_context();
struct lws *lws_mock_create_wsi();
struct lws *lws_mock_get_wsi();
void lws_mock_destroy_wsi(struct lws *wsi);
void lws_mock_connection_established(struct lws *wsi, enum lws_callback_reasons reason);
void lws_mock_connection_closed(struct lws *wsi);
void lws_mock_call_receive_cb(struct lws *wsi, void *in, size_t len);
void lws_mock_callback_client_receive(unsigned char *buf, size_t len, int expected_ret_val);
int lws_mock_callback(struct lws *wsi, enum lws_callback_reasons reason);
void lws_mock_setup_connection_failure();
#endif
