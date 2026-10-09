/* SPDX-License-Identifier: Apache-2.0 */
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "pal.h"
#include "pal_plat_rtos.h"
#include "pal_plat_fileSystem.h"
#include "pal_plat_entropy.h"

extern palStatus_t pal_plat_getRandomBufferFromHW(uint8_t *, size_t, size_t *);
#define CHECK(expression) do { if (!(expression)) { \
    fprintf(stderr, "%s:%d: %s failed (errno=%d)\n", __FILE__, __LINE__, #expression, errno); \
    exit(1); } } while (0)
#define OK(expression) CHECK((expression) == PAL_SUCCESS)

static void wait_idle(void)
{
    uint64_t deadline = pal_osKernelSysTick() + 3000000;
    while (pal_plat_RTOSDestroy() != PAL_SUCCESS && pal_osKernelSysTick() < deadline) pal_osDelay(1);
    OK(pal_plat_RTOSDestroy());
}

typedef struct worker_state {
    palMutexID_t mutex;
    palSemaphoreID_t ready;
    palSemaphoreID_t blocked;
    palThreadID_t observed_id;
} worker_state;

static void mutex_worker(const void *argument)
{
    worker_state *state = (worker_state *)argument;
    state->observed_id = pal_osThreadGetId();
    CHECK(pal_osMutexWait(state->mutex, 0) == PAL_ERR_RTOS_RESOURCE);
    uint64_t before = pal_osKernelSysTick();
    CHECK(pal_osMutexWait(state->mutex, 30) == PAL_ERR_RTOS_TIMEOUT);
    CHECK(pal_osKernelSysTick() - before >= 25000);
    CHECK(pal_osMutexRelease(state->mutex) == PAL_ERR_RTOS_PARAMETER);
    OK(pal_osSemaphoreRelease(state->ready));
}

static void cancellation_worker(const void *argument)
{
    worker_state *state = (worker_state *)argument;
    OK(pal_osSemaphoreRelease(state->ready));
    pal_osSemaphoreWait(state->blocked, PAL_RTOS_WAIT_FOREVER, NULL);
    CHECK(false);
}

static int32_t atomic_total;
static void atomic_worker(const void *argument)
{
    worker_state *state = (worker_state *)argument;
    uint64_t previous = pal_osKernelSysTick();
    for (int i = 0; i < 10000; ++i) {
        uint64_t now = pal_osKernelSysTick();
        CHECK(now >= previous && now - previous < 1000000);
        previous = now;
        pal_osAtomicIncrement(&atomic_total, 1);
    }
    OK(pal_osSemaphoreRelease(state->ready));
}

static void test_threads_and_waits(void)
{
    worker_state state = {0};
    palThreadID_t id;
    int32_t available = -1;
    OK(pal_osSemaphoreCreate(2, &state.ready));
    OK(pal_osSemaphoreWait(state.ready, 0, &available)); CHECK(available == 1);
    OK(pal_osSemaphoreWait(state.ready, 0, &available)); CHECK(available == 0);
    CHECK(pal_osSemaphoreWait(state.ready, 5, &available) == PAL_ERR_RTOS_TIMEOUT);
    CHECK(available == 0);
    OK(pal_osSemaphoreCreate(0, &state.blocked));
    OK(pal_osMutexCreate(&state.mutex));
    OK(pal_osMutexWait(state.mutex, 0));
    OK(pal_osMutexWait(state.mutex, 0));
    CHECK(pal_osMutexDelete(&state.mutex) == PAL_ERR_RTOS_RESOURCE);
    OK(pal_osThreadCreateWithAlloc(mutex_worker, &state, PAL_osPriorityNormal, 4096, NULL, &id));
    OK(pal_osSemaphoreWait(state.ready, 2000, NULL));
    CHECK(state.observed_id == id);
    wait_idle();
    OK(pal_osMutexRelease(state.mutex));
    OK(pal_osMutexRelease(state.mutex));
    OK(pal_osMutexDelete(&state.mutex)); CHECK(state.mutex == 0);
    for (int i = 0; i < 4; ++i) OK(pal_osThreadCreateWithAlloc(atomic_worker, &state, PAL_osPriorityNormal, 4096, NULL, &id));
    for (int i = 0; i < 4; ++i) OK(pal_osSemaphoreWait(state.ready, 2000, NULL));
    wait_idle();
    CHECK(atomic_total == 40000);
    for (int i = 0; i < 20; ++i) {
        OK(pal_osThreadCreateWithAlloc(cancellation_worker, &state, PAL_osPriorityNormal, 4096, NULL, &id));
        OK(pal_osSemaphoreWait(state.ready, 2000, NULL));
        OK(pal_osThreadTerminate(&id)); CHECK(id == 0);
        wait_idle();
        /* Canceled condition waits must release their internal lock. */
        OK(pal_osSemaphoreRelease(state.blocked));
        OK(pal_osSemaphoreWait(state.blocked, 0, NULL));
    }
    OK(pal_osSemaphoreDelete(&state.blocked));
    OK(pal_osSemaphoreDelete(&state.ready));
    palSemaphoreID_t full;
    OK(pal_osSemaphoreCreate(INT32_MAX, &full));
    CHECK(pal_osSemaphoreRelease(full) == PAL_ERR_RTOS_RESOURCE);
    OK(pal_osSemaphoreDelete(&full));
}

typedef struct timer_state {
    palSemaphoreID_t fired;
    palSemaphoreID_t release;
    palTimerID_t timer;
    atomic_int calls;
    atomic_bool deleted;
} timer_state;

static void timer_callback(const void *argument)
{
    timer_state *state = (timer_state *)argument;
    atomic_fetch_add(&state->calls, 1);
    OK(pal_osSemaphoreRelease(state->fired));
}

static void self_delete_callback(const void *argument)
{
    timer_state *state = (timer_state *)argument;
    OK(pal_osTimerDelete(&state->timer));
    CHECK(state->timer == 0);
    OK(pal_osSemaphoreRelease(state->fired));
}

static void blocking_callback(const void *argument)
{
    timer_state *state = (timer_state *)argument;
    OK(pal_osSemaphoreRelease(state->fired));
    OK(pal_osSemaphoreWait(state->release, 2000, NULL));
}

static void *delete_timer_worker(void *argument)
{
    timer_state *state = argument;
    OK(pal_osTimerDelete(&state->timer));
    atomic_store(&state->deleted, true);
    return NULL;
}

static void test_timers(void)
{
    timer_state state = {0};
    OK(pal_osSemaphoreCreate(0, &state.fired));
    OK(pal_osSemaphoreCreate(0, &state.release));
    OK(pal_osTimerCreate(timer_callback, &state, palOsTimerOnce, &state.timer));
    CHECK(pal_plat_RTOSDestroy() == PAL_ERR_RTOS_RESOURCE);
    CHECK(pal_osTimerStart(state.timer, 0) == PAL_ERR_RTOS_VALUE);
    OK(pal_osTimerStart(state.timer, 10));
    OK(pal_osTimerStart(state.timer, 100));
    CHECK(pal_osSemaphoreWait(state.fired, 30, NULL) == PAL_ERR_RTOS_TIMEOUT);
    OK(pal_osSemaphoreWait(state.fired, 1000, NULL));
    CHECK(pal_osSemaphoreWait(state.fired, 20, NULL) == PAL_ERR_RTOS_TIMEOUT);
    CHECK(atomic_load(&state.calls) == 1);
    OK(pal_osTimerDelete(&state.timer)); CHECK(state.timer == 0);
    OK(pal_osTimerCreate(timer_callback, &state, palOsTimerPeriodic, &state.timer));
    OK(pal_osTimerStart(state.timer, 5));
    for (int i = 0; i < 3; ++i) OK(pal_osSemaphoreWait(state.fired, 1000, NULL));
    OK(pal_osTimerDelete(&state.timer));
    while (pal_osSemaphoreWait(state.fired, 0, NULL) == PAL_SUCCESS) {}
    int stopped_calls = atomic_load(&state.calls);
    OK(pal_osDelay(20)); CHECK(atomic_load(&state.calls) == stopped_calls);
    for (int i = 0; i < 100; ++i) {
        OK(pal_osTimerCreate(timer_callback, &state, palOsTimerOnce, &state.timer));
        OK(pal_osTimerStart(state.timer, 1000));
        OK(pal_osTimerStop(state.timer));
        OK(pal_osTimerDelete(&state.timer));
    }
    CHECK(pal_osSemaphoreWait(state.fired, 20, NULL) == PAL_ERR_RTOS_TIMEOUT);
    OK(pal_osTimerCreate(self_delete_callback, &state, palOsTimerOnce, &state.timer));
    OK(pal_osTimerStart(state.timer, 5));
    OK(pal_osSemaphoreWait(state.fired, 1000, NULL));
    wait_idle(); CHECK(state.timer == 0);
    OK(pal_osTimerCreate(blocking_callback, &state, palOsTimerOnce, &state.timer));
    OK(pal_osTimerStart(state.timer, 5));
    OK(pal_osSemaphoreWait(state.fired, 1000, NULL));
    pthread_t deleter;
    CHECK(pthread_create(&deleter, NULL, delete_timer_worker, &state) == 0);
    OK(pal_osDelay(20)); CHECK(!atomic_load(&state.deleted));
    OK(pal_osSemaphoreRelease(state.release));
    CHECK(pthread_join(deleter, NULL) == 0);
    CHECK(atomic_load(&state.deleted));
    wait_idle();
    OK(pal_osSemaphoreDelete(&state.fired));
    OK(pal_osSemaphoreDelete(&state.release));
}

static void test_entropy_and_storage(void)
{
    uint8_t first[1024], second[1024];
    size_t actual = 0;
    OK(pal_plat_getRandomBufferFromHW(first, sizeof(first), &actual)); CHECK(actual == sizeof(first));
    OK(pal_plat_getRandomBufferFromHW(second, sizeof(second), &actual));
    CHECK(memcmp(first, second, sizeof(first)) != 0);
    CHECK(pal_plat_getRandomBufferFromHW(NULL, 1, &actual) == PAL_ERR_INVALID_ARGUMENT); CHECK(actual == 0);
    OK(pal_plat_getRandomBufferFromHW(NULL, 0, &actual));
    char root[] = "/tmp/edge-pal-XXXXXX";
    CHECK(mkdtemp(root) != NULL);
    char path[sizeof(root) + 20];
    mode_t previous_mask = umask(0);
    CHECK(snprintf(path, sizeof(path), "%s/identity", root) > 0);
    palFileDescriptor_t file, duplicate;
    OK(pal_fsFopen(path, PAL_FS_FLAG_READWRITEEXCLUSIVE, &file));
    CHECK(pal_fsFopen(path, PAL_FS_FLAG_READWRITEEXCLUSIVE, &duplicate) == PAL_ERR_FS_NAME_ALREADY_EXIST);
    OK(pal_fsFwrite(&file, first, sizeof(first), &actual)); CHECK(actual == sizeof(first));
    OK(pal_fsFclose(&file));
    struct stat metadata;
    CHECK(stat(path, &metadata) == 0 && (metadata.st_mode & 0777) == 0600);
    OK(pal_fsFopen(path, PAL_FS_FLAG_READONLY, &file));
    OK(pal_fsFread(&file, second, sizeof(second), &actual));
    CHECK(actual == sizeof(first) && memcmp(first, second, sizeof(first)) == 0);
    OK(pal_fsFclose(&file));
    char link_path[sizeof(root) + 20];
    CHECK(snprintf(link_path, sizeof(link_path), "%s/identity.link", root) > 0);
    CHECK(symlink(path, link_path) == 0);
    CHECK(pal_fsFopen(link_path, PAL_FS_FLAG_READONLY, &file) != PAL_SUCCESS);
    CHECK(unlink(link_path) == 0);
    OK(pal_fsUnlink(path));
    CHECK(snprintf(path, sizeof(path), "%s/private", root) > 0);
    OK(pal_fsMkDir(path));
    CHECK(stat(path, &metadata) == 0 && (metadata.st_mode & 0777) == 0700);
    OK(pal_fsRmDir(path));
    umask(previous_mask);
    OK(pal_fsRmDir(root));
    CHECK(pal_plat_fsFormat(PAL_FS_PARTITION_PRIMARY) == PAL_ERR_NOT_SUPPORTED);
}

int main(void)
{
    umask(0077);
    OK(pal_plat_RTOSInitialize(NULL));
    CHECK(pal_osKernelSysTickFrequency() == 1000000);
    CHECK(pal_osKernelSysTickMicroSec(1001) == 1001);
    test_threads_and_waits();
    test_timers();
    test_entropy_and_storage();
    wait_idle();
    OK(pal_plat_RTOSInitialize(NULL));
    OK(pal_plat_RTOSDestroy());
    puts("macOS PAL runtime, cancellation, timers, entropy and storage passed");
    return 0;
}
