#include "CppUTest/TestHarness.h"
#include "CppUTestExt/MockSupport.h"
#include "test-lib/mutex_helper.h"

void mh_expect_mutex_init(edge_mutex_t *mutex, int32_t type)
{
    mock().expectOneCall("edge_mutex_init")
            .withPointerParameter("mutex", mutex)
            .withIntParameter("type", type)
            .andReturnValue(0);
}

void mh_expect_mutexing(edge_mutex_t *mutex)
{
    mh_expect_mutex_lock(mutex);
    mh_expect_mutex_unlock(mutex);
}

void mh_expect_mutex_lock(edge_mutex_t *mutex)
{
    mock().expectOneCall("edge_mutex_lock").withPointerParameter("mutex", mutex).andReturnValue(0);
}

void mh_expect_mutex_unlock(edge_mutex_t *mutex)
{
    mock().expectOneCall("edge_mutex_unlock").withPointerParameter("mutex", mutex).andReturnValue(0);
}

