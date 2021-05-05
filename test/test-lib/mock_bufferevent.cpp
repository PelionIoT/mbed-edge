
#include "CppUTest/TestHarness.h"
#include "CppUTestExt/MockSupport.h"
extern "C" {
#include "jansson.h"
#include <string.h>
#include <assert.h>
#include "test-lib/evbase_mock.h"
#include "event2/bufferevent.h"
#include <event2/buffer.h>
#include "cpputest-custom-types/my_json_frame.h"

struct bufferevent *bufferevent_socket_new(struct event_base *base, evutil_socket_t fd, int options)
{
    struct bufferevent *ret_val = (struct bufferevent *)mock()
            .actualCall("bufferevent_socket_new")
            .returnPointerValue();
    if (ret_val) {
        ret_val->base = base;
    }
    return ret_val;
}

evutil_socket_t bufferevent_getfd(struct bufferevent *bufev) {
    return mock()
            .actualCall("bufferevent_getfd")
            .returnIntValue();
}

void bufferevent_free(struct bufferevent *bufev)
{
   mock().actualCall("bufferevent_free")
            .withPointerParameter("bufev", (void *)bufev);
}

struct evbuffer *bufferevent_get_input(struct bufferevent *bufev)
{
    return (evbuffer *) mock()
            .actualCall("bufferevent_get_input")
            .returnPointerValue();
}

struct evbuffer *bufferevent_get_output(struct bufferevent *bufev)
{
    return (evbuffer *) mock()
            .actualCall("bufferevent_get_output")
            .returnPointerValue();
}

void bufferevent_setcb(struct bufferevent *bufev,
    bufferevent_data_cb readcb, bufferevent_data_cb writecb,
    bufferevent_event_cb eventcb, void *cbarg)
{
    mock().actualCall("bufferevent_setcb")
            .withPointerParameter("bufev", (void *) bufev)
            .withPointerParameter("readcb", (void *) readcb)
            .withPointerParameter("writecb", (void *) writecb)
            .withPointerParameter("eventcb", (void *) eventcb);
    if (bufev) {
        bufev->connection = (struct connection *) cbarg;
    }
}

int bufferevent_enable(struct bufferevent *bufev, short event)
{
    mock().actualCall("bufferevent_enable");
    return 0;
}

int bufferevent_socket_connect(struct bufferevent *event, const struct sockaddr *addr, int socklen)
{
    return mock().actualCall("bufferevent_socket_connect")
            .returnIntValue();
}

int bufferevent_write(struct bufferevent *bufev, const void *data, size_t size)
{
    /*
     * Assert that the size in message equals the data size of the data
     */
    assert(htonl((int)((size_t *)data)[0]) == size - 4);

    MyJsonFrame *frame = new MyJsonFrame((const char *)data);
    int retVal = mock().actualCall("bufferevent_write")
        .withParameterOfType("MyJsonFrame", "data", (const void *)frame)
        .returnIntValue();
    delete frame;
    return retVal;
}

size_t bufferevent_read(struct bufferevent *bufev, void *data, size_t size)
{
    return mock().actualCall("bufferevent_read")
            .withOutputParameter("data", data)
            .returnIntValue();
}

} /* extern "C" */
