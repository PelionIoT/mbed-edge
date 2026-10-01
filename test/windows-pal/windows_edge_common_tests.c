/* SPDX-License-Identifier: Apache-2.0 */
#include <windows.h>
#include <process.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "common/edge_mutex.h"
#include "common/edge_time.h"
#include "common/edge_platform.h"
#include "common/edge_io_lib.h"
#include "common/read_file.h"

#define CHECK(expression) do { if (!(expression)) { \
    fprintf(stderr, "%s:%d: %s failed\n", __FILE__, __LINE__, #expression); exit(1); \
} } while (0)

static edge_mutex_t mutex;
static int counter;

static unsigned __stdcall increment(void *arg)
{
    (void)arg;
    CHECK(edge_mutex_unlock(&mutex) == EPERM);
    for (int i = 0; i < 1000; ++i) {
        CHECK(edge_mutex_lock(&mutex) == 0);
        ++counter;
        CHECK(edge_mutex_unlock(&mutex) == 0);
    }
    return 0;
}

static void test_mutex(int type)
{
    CHECK(edge_mutex_init(&mutex, type) == 0);
    CHECK(edge_mutex_lock(&mutex) == 0);
    CHECK(edge_mutex_destroy(&mutex) == EBUSY);
    if (type == EDGE_MUTEX_RECURSIVE) {
        CHECK(edge_mutex_lock(&mutex) == 0);
        CHECK(edge_mutex_unlock(&mutex) == 0);
    } else if (type == EDGE_MUTEX_ERRORCHECK) {
        CHECK(edge_mutex_lock(&mutex) == EDEADLK);
    }
    HANDLE threads[2];
    counter = 0;
    for (int i = 0; i < 2; ++i) {
        threads[i] = (HANDLE)_beginthreadex(NULL, 0, increment, NULL, 0, NULL);
        CHECK(threads[i] != NULL);
    }
    CHECK(edge_mutex_unlock(&mutex) == 0);
    CHECK(WaitForMultipleObjects(2, threads, TRUE, 5000) == WAIT_OBJECT_0);
    CHECK(counter == 2000);
    for (int i = 0; i < 2; ++i) CloseHandle(threads[i]);
    CHECK(edge_mutex_destroy(&mutex) == 0);
}

int main(void)
{
    test_mutex(EDGE_MUTEX_NORMAL);
    test_mutex(EDGE_MUTEX_RECURSIVE);
    test_mutex(EDGE_MUTEX_ERRORCHECK);
    uint64_t before = edgetime_get_monotonic_in_ms();
    CHECK(before > 0);
    CHECK(pal_osDelay(25) == PAL_SUCCESS);
    CHECK(edgetime_get_monotonic_in_ms() >= before + 10);
    uint64_t seconds, nanoseconds;
    CHECK(edgetime_get_real_in_ns(&seconds, &nanoseconds));
    CHECK(nanoseconds < 1000000000);
    CHECK(llabs((long long)seconds - (long long)time(NULL)) <= 1);

    char *message;
    CHECK(asprintf(&message, "%s:%d/%llu", "timeout", 500, 1234567890123ULL) == 25);
    CHECK(strcmp(message, "timeout:500/1234567890123") == 0);
    free(message);
    char tokens[] = "device/3/0/1";
    char *state;
    CHECK(strcmp(strtok_r(tokens, "/", &state), "device") == 0);
    CHECK(strcmp(strtok_r(NULL, "/", &state), "3") == 0);
    CHECK(strcmp(strtok_r(NULL, "/", &state), "0") == 0);
    CHECK(strcmp(strtok_r(NULL, "/", &state), "1") == 0);
    CHECK(strtok_r(NULL, "/", &state) == NULL);

    int first, second;
    const char *lock_path = "edge-common-test";
    CHECK(edge_io_acquire_lock_for_socket(lock_path, &first));
    CHECK(!edge_io_acquire_lock_for_socket(lock_path, &second));
    CHECK(edge_io_release_lock_for_socket(lock_path, first));
    CHECK(edge_io_acquire_lock_for_socket(lock_path, &second));
    CHECK(edge_io_release_lock_for_socket(lock_path, second));
    CHECK(edge_io_unlink("edge-common-test.lock") == 0);
    const uint8_t binary[] = {0x00, 0x0d, 0x0a, 0x1a, 0xff};
    FILE *file = fopen("edge-common-test.cbor", "wb");
    CHECK(file != NULL);
    CHECK(fwrite(binary, 1, sizeof(binary), file) == sizeof(binary));
    CHECK(fclose(file) == 0);
    uint8_t *data;
    size_t length;
    CHECK(edge_read_file("edge-common-test.cbor", &data, &length) == 0);
    CHECK(length == sizeof(binary) && memcmp(binary, data, length) == 0);
    free(data);
    CHECK(edge_io_unlink("edge-common-test.cbor") == 0);
    puts("PASS Edge PAL mutexes, clocks, formatting, tokenizer, file locks and binary provisioning reads");
    return 0;
}
