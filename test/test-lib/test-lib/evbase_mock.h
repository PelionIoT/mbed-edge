#ifndef EVBASE_MOCK_H_
#define EVBASE_MOCK_H_

#include <pthread.h>
#include <event2/event.h>
/* Implementation of the libevent evbase internal structures */
struct event_base {
    pthread_mutex_t event_loop_simulation_lock;
    pthread_mutex_t wait_lock;
    pthread_mutex_t event_lock;
    pthread_mutex_t interrupt_lock;
    struct event *assigned_event;
    bool event_add_releases_event_lock;
    bool event_loop_wait_simulation;
    bool event_loop_started;
};

struct bufferevent {
    struct event_base *base;
    struct connection *connection;
};

struct evconnlistener {
    bool dummy;
};

struct event {
   event_callback_fn cb;
   void *cb_arg;
   int fd;
   int events;
   struct event_base *base;
};

struct event_base *evbase_mock_new();
void evbase_mock_delete(struct event_base *base);
void evbase_mock_call_assigned_event_cb(struct event_base *base, bool lock_mutex);
void evbase_mock_setup_event_loop_wait(struct event_base *base);
void evbase_mock_acquire_event_loop_lock(struct event_base *base);
void evbase_mock_release_event_loop_lock_and_block_interrupt(struct event_base *base);
void evbase_mock_release_interrupt_thread(struct event_base *base);

void evbase_mock_wait_until_event_loop(struct event_base *base);

#endif
