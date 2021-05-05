#include "CppUTestExt/MockSupport.h"
#include <assert.h>
#include "event-os-mock/eventOS_event_mock.h"
extern "C" {
#include "ns_list.h"
}

static os_event_items_t *event_list = NULL;
static os_event_handlers_t *event_handler_list = NULL;

void eventOS_mock_init()
{
    assert(NULL == event_list);
    assert(NULL == event_handler_list);
    event_list = (os_event_items_t *) calloc(1, sizeof(os_event_items_t));
    event_handler_list = (os_event_handlers_t *) calloc(1, sizeof(os_event_handlers_t));
    ns_list_init(event_list);
    ns_list_init(event_handler_list);
}

void eventOS_mock_destroy()
{
    ns_list_foreach_safe(os_event_handler_t, cur, event_handler_list)
    {
        ns_list_remove(event_handler_list, cur);
        free(cur);
    }
    CHECK_EQUAL(0, ns_list_count(event_list));
    CHECK_EQUAL(0, ns_list_count(event_handler_list));
    free(event_list);
    event_list = NULL;
    free(event_handler_list);
    event_handler_list = NULL;
}

int8_t eventOS_event_handler_create(void (*handler_func_ptr)(arm_event_t *), uint8_t init_event_type)
{
    if (event_handler_list) {
        os_event_handler_t *handler = (os_event_handler_t *) calloc(1, sizeof(os_event_handler_t));
        handler->handler_func = handler_func_ptr;
        handler->init_event_type = init_event_type;
        ns_list_add_to_end(event_handler_list, handler);
    }
    return (int8_t) mock()
            .actualCall("eventOS_event_handler_create")
            .withPointerParameter("handler_func_ptr", (void *) handler_func_ptr)
            .withIntParameter("init_event_type", init_event_type)
            .returnIntValue();
}

int8_t eventOS_event_send(const arm_event_t *event)
{
    int8_t ret_val = (int8_t) mock()
                             .actualCall("eventOS_event_send")
                             .withIntParameter("event_id", event->event_id)
                             .withIntParameter("receiver", event->receiver)
                             .returnIntValue();
    if (event_list && ret_val == 0) {
        os_event_item_t *item = (os_event_item_t *) calloc(1, sizeof(os_event_item_t));
        item->event = *event;
        ns_list_add_to_end(event_list, item);
    }
    return ret_val;
}

bool eventOS_mock_event_handle()
{
    os_event_item_t *event = ns_list_get_first(event_list);
    if (!event) {
        return false;
    }

    ns_list_remove(event_list, event);
    ns_list_foreach_safe(os_event_handler_t, cur, event_handler_list)
    {
        if (cur->init_event_type == event->event.event_type) {
            cur->handler_func(&(event->event));
            free(event);
            return true;
        }
    }
    free(event);
    return false;
}

void eventOS_scheduler_mutex_wait()
{
    mock().actualCall("eventOS_scheduler_mutex_wait");
}

void eventOS_scheduler_mutex_release()
{
    mock().actualCall("eventOS_scheduler_mutex_release");
}
