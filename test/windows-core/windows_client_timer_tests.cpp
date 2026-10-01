/* SPDX-License-Identifier: Apache-2.0 */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include "pal.h"
#include "ns_hal_init.h"
#include "ns_event_loop.h"
#include "eventOS_scheduler.h"
#include "mbed-client/m2mtimer.h"
#include "mbed-client/m2mtimerobserver.h"

#define CHECK(value) do { if (!(value)) { \
    fprintf(stderr, "Client timer test line %d: %s failed\n", __LINE__, #value); exit(1); \
} } while (0)

class TimerObserver : public M2MTimerObserver {
public:
    palSemaphoreID_t completed = 0;
    Type received = Notdefined;
    LARGE_INTEGER fired_at = {};
    void timer_expired(Type type) override {
        received = type;
        CHECK(QueryPerformanceCounter(&fired_at));
        CHECK(pal_osSemaphoreRelease(completed) == PAL_SUCCESS);
    }
};

int main()
{
    CHECK(pal_init() == PAL_SUCCESS);
    ns_hal_init(NULL, 65536, NULL, NULL);
    TimerObserver observer;
    CHECK(pal_osSemaphoreCreate(0, &observer.completed) == PAL_SUCCESS);
    {
        M2MTimer timer(observer);
        /* Check the real C++ timer -> C scheduler -> Windows PAL callback
         * boundary, including zero-delay cloud bootstrap and all timer types. */
        const uint64_t delays[] = {0, 25};
        for (int type = M2MTimerObserver::Notdefined; type < M2MTimerObserver::TypeNotUsed; ++type) {
            for (uint64_t delay : delays) {
                eventOS_scheduler_mutex_wait();
                timer.start_timer(delay, static_cast<M2MTimerObserver::Type>(type));
                eventOS_scheduler_mutex_release();
                CHECK(pal_osSemaphoreWait(observer.completed, 3000, NULL) == PAL_SUCCESS);
                // Wait until the callback and its scheduler dispatch finish.
                eventOS_scheduler_mutex_wait();
                if (observer.received != type) {
                    fprintf(stderr, "Timer type %d arrived as %d\n", type, observer.received);
                    return 1;
                }
                eventOS_scheduler_mutex_release();
            }
        }
        /* Registration timers must track elapsed time, including delayed HAL
         * callbacks. Windows may coalesce its short periodic timer wakes. */
        LARGE_INTEGER frequency, started;
        CHECK(QueryPerformanceFrequency(&frequency));
        eventOS_scheduler_mutex_wait();
        CHECK(QueryPerformanceCounter(&started));
        timer.start_timer(5000, M2MTimerObserver::Registration);
        // Simulate a busy critical section that holds up the HAL callback.
        Sleep(1500);
        eventOS_scheduler_mutex_release();
        CHECK(pal_osSemaphoreWait(observer.completed, 12000, NULL) == PAL_SUCCESS);
        eventOS_scheduler_mutex_wait();
        double elapsed_ms = 1000.0 * (observer.fired_at.QuadPart - started.QuadPart) / frequency.QuadPart;
        printf("Registration timer: %.1f ms for a 5000 ms deadline with a 1500 ms callback stall\n", elapsed_ms);
        CHECK(observer.received == M2MTimerObserver::Registration);
        CHECK(elapsed_ms >= 4900.0 && elapsed_ms <= 6500.0);
        eventOS_scheduler_mutex_release();
    }
    CHECK(pal_osSemaphoreDelete(&observer.completed) == PAL_SUCCESS);
    ns_event_loop_thread_stop();
    puts("PASS shared client timer types, immediate and delayed delivery through Windows PAL");
    return 0;
}
