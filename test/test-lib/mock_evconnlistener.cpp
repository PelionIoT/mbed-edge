#include "CppUTest/TestHarness.h"
#include "CppUTestExt/MockSupport.h"
extern "C" {
#include <string.h>
#include <stdlib.h>
#include "event2/listener.h"


struct evconnlistener *evconnlistener_new_bind(struct event_base *base, evconnlistener_cb cb,
    void *ptr, unsigned flags, int backlog, const struct sockaddr *sa, int socklen)
{
    return (struct evconnlistener *) mock().actualCall("evconnlistener_new_bind")
            .returnPointerValue();
}

void evconnlistener_set_error_cb(struct evconnlistener *lev, evconnlistener_errorcb errorcb)
{
    mock().actualCall("evconnlistener_set_error_cb");
}

} /* extern "C" */
