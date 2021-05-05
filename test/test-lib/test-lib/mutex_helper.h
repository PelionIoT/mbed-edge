#ifndef EDGE_MUTEX_HELPER_H
#define EDGE_MUTEX_HELPER_H

extern "C" {
#include "common/edge_mutex.h"
};

void mh_expect_mutex_init(edge_mutex_t *mutex, int32_t type);
void mh_expect_mutexing(edge_mutex_t *mutex);
void mh_expect_mutex_lock(edge_mutex_t *mutex);
void mh_expect_mutex_unlock(edge_mutex_t *mutex);

#endif

