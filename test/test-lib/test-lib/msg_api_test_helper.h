#ifndef MSG_API_TEST_HELPER_H
#define MSG_API_TEST_HELPER_H
extern "C" {
#include "common/msg_api.h"
void event_cb(evutil_socket_t fd, short what, void *arg);
}

void expect_event_message(struct event_base *base, event_loop_callback_t callback, bool succeeds);
void expect_event_message_without_get_base(struct event_base *base, event_loop_callback_t callback, bool succeeds);

#endif


