#include "CppUTest/TestHarness.h"
#include "CppUTestExt/MockSupport.h"
#include "test-lib/MyEvBuffer.h"
extern "C" {
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "event2/bufferevent.h"
#include "event2/listener.h"
#include "test-lib/evbase_mock.h"
#include <pthread.h>

struct event_base *bufferevent_get_base(struct bufferevent *bev) {
    return (event_base * ) mock().actualCall("bufferevent_get_base")
        .returnPointerValue();
}

struct evbuffer *evbuffer_new(void)
{
    return (struct evbuffer * ) mock().actualCall("evbuffer_new")
            .returnPointerValue();
}

void evbuffer_free(struct evbuffer *buf)
{
    mock().actualCall("evbuffer_free")
            .withPointerParameter("buf", (void *) buf);
}

int evbuffer_add(struct evbuffer *buf, const void *data, size_t datlen)
{
    MyEvBuffer buffer((char *) data);
    return mock()
            .actualCall("evbuffer_add")
            .withPointerParameter("buf", (void *) buf)
            .withParameterOfType("MyEvBuffer", "data", (void *) &buffer)
            .returnIntValue();
}

size_t evbuffer_get_length(const struct evbuffer *buf)
{
    return (size_t) mock().actualCall("evbuffer_get_length")
            .withPointerParameter("buf", (void *) buf)
            .returnUnsignedIntValue();
}

ev_ssize_t evbuffer_copyout(struct evbuffer *buf, void *data_out, size_t datlen)
{
    return (ev_ssize_t) mock().actualCall("evbuffer_copyout")
                .withPointerParameter("buf", buf)
                .withOutputParameter("data_out", data_out)
                .withUnsignedIntParameter("datlen", datlen)
                .returnUnsignedIntValue();
}

int evbuffer_expand(struct evbuffer *buf, size_t datlen)
{
    return mock()
            .actualCall("evbuffer_expand")
            .withPointerParameter("buf", (void *) buf)
            .withUnsignedIntParameter("datlen", datlen)
            .returnIntValue();
}

unsigned char *evbuffer_pullup(struct evbuffer *buf, ev_ssize_t size)
{
    return (unsigned char *) mock()
            .actualCall("evbuffer_pullup")
            .withPointerParameter("buf", (void *) buf)
            .withUnsignedIntParameter("size", size)
            .returnPointerValue();
}

int evbuffer_drain(struct evbuffer *buf, size_t len)
{
    return mock().actualCall("evbuffer_drain")
            .withPointerParameter("buf", (void *) buf)
            .withUnsignedIntParameter("len", len)
            .returnIntValue();
}

int evbuffer_remove(struct evbuffer *buf, void *data, size_t datlen)
{
    return mock().actualCall("evbuffer_remove")
            .withPointerParameter("data", (void *) data)
            .withUnsignedIntParameter("datlen", datlen)
            .returnIntValue();
}

struct event_base *evconnlistener_get_base(struct evconnlistener *lev)
{
    return (event_base *) mock().actualCall("evconnlistener_get_base")
            .withPointerParameter("lev", (void *) lev)
            .returnPointerValue();
}

int evconnlistener_disable(struct evconnlistener *lev)
{
    return mock().actualCall("evconnlistener_disable")
            .withPointerParameter("lev", (void *) lev)
            .returnIntValue();
}

void evconnlistener_set_cb(struct evconnlistener *lev, evconnlistener_cb cb, void *arg)
{
    mock().actualCall("evconnlistener_set_cb")
            .withPointerParameter("lev", (void *) lev)
            .withPointerParameter("cb", (void *) cb)
            .withPointerParameter("arg", (void *) arg);
}

void evconnlistener_free(struct evconnlistener *lev)
{
    mock().actualCall("evconnlistener_free")
            .withPointerParameter("lev", lev);
}

int evutil_closesocket(evutil_socket_t sock)
{
    return mock().actualCall("evutil_closesocket").withIntParameter("sock", sock).returnIntValue();
}

void evbase_mock_acquire_event_loop_lock(struct event_base *base)
{
    pthread_mutex_lock(&base->event_loop_simulation_lock);
}

void evbase_mock_release_event_loop_lock_and_block_interrupt(struct event_base *base)
{
    assert(base->event_loop_wait_simulation);
    pthread_mutex_unlock(&base->event_loop_simulation_lock);
    pthread_mutex_lock(&base->interrupt_lock);
}

void evbase_mock_release_interrupt_thread(struct event_base *base)
{
    pthread_mutex_unlock(&base->interrupt_lock);
}

void evbase_mock_wait_until_event_loop(struct event_base *base)
{
    pthread_mutex_lock(&base->wait_lock);
}

void evbase_mock_setup_event_loop_wait(struct event_base *base)
{
    base->event_loop_wait_simulation = true;
    pthread_mutex_lock(&base->wait_lock);
    // setup also the interrupt lock so we can control that it resumes running
    // after the main program is finished.
    pthread_mutex_lock(&base->interrupt_lock);
    evbase_mock_acquire_event_loop_lock(base);
}

struct event_base *evbase_mock_new()
{
    struct event_base *base = (struct event_base *) calloc(1, sizeof(struct event_base));
    pthread_mutex_init(&base->event_lock, NULL);
    pthread_mutex_init(&base->event_loop_simulation_lock, NULL);
    pthread_mutex_init(&base->wait_lock, NULL);
    pthread_mutex_init(&base->interrupt_lock, NULL);
    return base;
}

void evbase_mock_delete(struct event_base *base)
{
    if (base) {
        pthread_mutex_destroy(&base->event_lock);
        pthread_mutex_destroy(&base->event_loop_simulation_lock);
        pthread_mutex_destroy(&base->wait_lock);
        pthread_mutex_destroy(&base->interrupt_lock);
        free(base);
    }
}

struct event_base *event_base_new(void)
{
    struct event_base *base = (struct event_base *) mock()
            .actualCall("event_base_new")
            .returnPointerValue();
    return base;
}

void event_base_free(struct event_base *base)
{
    mock().actualCall("event_base_free")
            .withPointerParameter("base", (void *) base);
}

int event_base_loopexit(struct event_base* base, const struct timeval *tv)
{
    int ret_val = mock().actualCall("event_base_loopexit")
                          .withPointerParameter("base", (void *) base)
                          .withPointerParameter("tv", (void *) tv)
                          .returnIntValue();

    if (base->event_loop_started) {
        evbase_mock_release_event_loop_lock_and_block_interrupt(base);
    }
    return ret_val;
}

int event_base_loopbreak(struct event_base* base)
{
    if (base->event_loop_started) {
        evbase_mock_release_event_loop_lock_and_block_interrupt(base);
    }
    return mock().actualCall("event_base_loopbreak")
                 .withPointerParameter("base", (void *) base)
                 .returnIntValue();
}

int event_base_dispatch(struct event_base *base)
{
    int ret_val = mock()
        .actualCall("event_base_dispatch")
        .withPointerParameter("base", base)
        .returnIntValue();
        //printf("dsadasdsa %d", ret_val);
    base->event_loop_started = true;
    if (ret_val == 0 && base->event_loop_wait_simulation) {
        // release the thread waiting for event loop
        pthread_mutex_unlock(&base->wait_lock);
        // start event loop simulation
        evbase_mock_acquire_event_loop_lock(base);
    }
    return ret_val;
}

void event_free(struct event *ev)
{
    mock().actualCall("event_free")
            .withPointerParameter("ev", (void *) ev);
}

int evthread_use_pthreads()
{
    return mock().actualCall("evthread_use_pthreads").returnIntValue();
}



int event_add(struct event *ev, const struct timeval *timeout)
{
    struct event_base *base = ev->base;
    int ret_val = mock().actualCall("event_add").returnIntValue();
    if (base->event_add_releases_event_lock) {
        pthread_mutex_unlock(&base->event_lock);
    }
    return ret_val;
}

void event_active(struct event *ev, int res, short ncalls)
{
    mock().actualCall("event_active");
    /*
            .withPointerParameter("ev", (void *) ev)
            .withIntParameter("res", res)
            .withIntParameter("ncalls", ncalls);*/
}

void event_mock_call_cb(struct event *ev)
{
    ev->cb(ev->fd, ev->events, ev->cb_arg);
}

size_t event_get_struct_event_size(void)
{
    mock().actualCall("event_get_struct_event_size");
    return sizeof(struct event);
}

int event_assign(struct event *ev,
                 struct event_base *base,
                 evutil_socket_t fd,
                 short events,
                 event_callback_fn cb,
                 void *arg)
{
    ev->cb = cb;
    ev->cb_arg = arg;
    ev->fd = fd;
    ev->events = events;
    ev->base = base;
    base->assigned_event = ev;
    return mock()
            .actualCall("event_assign")
            .withPointerParameter("base", (void *) base)
            .withIntParameter("fd", fd)
            .withIntParameter("events", events)
            .withPointerParameter("cb", (void *) cb)
            .returnIntValue();
}

void evbase_mock_call_assigned_event_cb(struct event_base *base, bool lock_mutex)
{
    struct event *ev = base->assigned_event;
    base->event_add_releases_event_lock = true;
    ev->cb(ev->fd, ev->events, ev->cb_arg);
    if (lock_mutex) {
        pthread_mutex_lock(&base->event_lock);
    }
}

void libevent_global_shutdown(void)
{
    mock().actualCall("libevent_global_shutdown");
}

struct event *event_new(struct event_base *base,
                        evutil_socket_t fd,
                        short flags,
                        event_callback_fn callback_fn,
                        void *arg)
{
    return (struct event *) mock()
            .actualCall("event_new")
            .withPointerParameter("base", base)
            .withIntParameter("fd", fd)
            .withIntParameter("flags", flags)
            .withPointerParameter("callback_fn", (void *) callback_fn)
            // .withPointerParameter("arg", arg)
            .returnPointerValue();
}

int event_del(struct event *ev)
{
    return mock().actualCall("event_del").withPointerParameter("ev", ev).returnIntValue();
}

} /* extern "C" */
