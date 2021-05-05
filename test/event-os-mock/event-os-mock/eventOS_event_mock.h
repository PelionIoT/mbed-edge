#ifndef EVENT_OS_EVENT_MOCK_H
#define EVENT_OS_EVENT_MOCK_H

#include "nanostack-event-loop/eventOS_scheduler.h"
#include "nanostack-event-loop/eventOS_event.h"

/* Simulates event OS */
typedef struct os_event_item {
    ns_list_link_t link;
    arm_event_t event;
} os_event_item_t;

typedef NS_LIST_HEAD(os_event_item_t, link) os_event_items_t;

typedef struct os_event_handler {
    ns_list_link_t link;
    void (*handler_func)(arm_event_t *);
    uint8_t init_event_type;
} os_event_handler_t;

typedef NS_LIST_HEAD(os_event_handler_t, link) os_event_handlers_t;

void eventOS_mock_init();
void eventOS_mock_destroy();
bool eventOS_mock_event_handle();
void eventOS_scheduler_mutex_wait();
void eventOS_scheduler_mutex_release();


#endif
