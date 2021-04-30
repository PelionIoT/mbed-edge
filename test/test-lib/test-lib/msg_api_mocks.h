#ifndef MSG_API_MOCKS_H
#define MSG_API_MOCKS_H

#include "ns_list.h"

typedef void (*event_loop_callback_t)(void *data);

typedef struct {
    ns_list_link_t link;
    void *data;
    event_loop_callback_t callback;
    int32_t timeout_in_ms;
} event_loop_message_t;

// FIFO event queue which can be used to check the event messages
typedef NS_LIST_HEAD(event_loop_message_t, link) event_loop_messages_t;

void mock_msg_api_messages_init();
void mock_msg_api_wipeout_messages();
int32_t mock_msg_api_messages_in_queue();
event_loop_message_t *mock_msg_api_pop_message();

#endif
