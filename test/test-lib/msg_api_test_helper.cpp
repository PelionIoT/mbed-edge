#include "CppUTest/TestHarness.h"
#include "CppUTestExt/MockSupport.h"
#include "test-lib/msg_api_test_helper.h"
extern "C" {
#include "common/msg_api.h"
}

static void expect_event_message_common(struct event_base *base,
                                        event_loop_callback_t callback,
                                        bool expect_get_base,
                                        bool succeeds)
{
    int event_assign_ret_val = 0;
    if (expect_get_base) {
        mock().expectOneCall("edge_server_get_base").andReturnValue(base);
    }
    mock().expectOneCall("event_get_struct_event_size");
    if (!succeeds) {
        event_assign_ret_val = -1;
    }
    mock().expectOneCall("event_assign")
            .withPointerParameter("base", (void *) base)
            .withIntParameter("fd", -1)
            .withIntParameter("events", 0)
            .withPointerParameter("cb", (void *) event_cb)
            .andReturnValue(event_assign_ret_val);
    if (succeeds) {
        mock().expectOneCall("event_add").andReturnValue(0);
        mock().expectOneCall("event_active");
    }
}

void expect_event_message(struct event_base *base, event_loop_callback_t callback, bool succeeds)
{
    expect_event_message_common(base, callback, true, succeeds);
}

void expect_event_message_without_get_base(struct event_base *base, event_loop_callback_t callback, bool succeeds)
{
    expect_event_message_common(base, callback, false, succeeds);
}

