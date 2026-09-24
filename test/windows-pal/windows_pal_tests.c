/* SPDX-License-Identifier: Apache-2.0 */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pal.h"
#include "pal_plat_rtos.h"
#include "pal_plat_network.h"
#include "pal_plat_fileSystem.h"
#include "pal_plat_entropy.h"

/* The board hook is declared locally by PAL's generic DRBG implementation. */
extern palStatus_t pal_plat_getRandomBufferFromHW(uint8_t *, size_t, size_t *);

#define CHECK(expression) do { if (!(expression)) { \
    fprintf(stderr, "%s:%d: %s failed (Win32=%lu, WSA=%d)\n", __FILE__, __LINE__, #expression, GetLastError(), WSAGetLastError()); \
    exit(1); } } while (0)
#define OK(expression) CHECK((expression) == PAL_SUCCESS)

static palSemaphoreID_t completed;
static palMutexID_t mutex;
static volatile LONG total;
static palThreadID_t observed_id;

static void mutex_worker(const void *unused)
{
    (void)unused;
    observed_id = pal_osThreadGetId();
    CHECK(pal_osMutexWait(mutex, 30) == PAL_ERR_RTOS_TIMEOUT);
    OK(pal_osSemaphoreRelease(completed));
}
static void atomic_worker(const void *unused)
{
    uint64_t before = pal_osKernelSysTick();
    (void)unused;
    for (int i = 0; i < 10000; ++i) {
        uint64_t now = pal_osKernelSysTick();
        CHECK(now >= before && now - before < 10000);
        before = now;
        pal_osAtomicIncrement((int32_t *)&total, 1);
    }
    OK(pal_osSemaphoreRelease(completed));
}
static void cancellable_worker(const void *unused)
{
    (void)unused;
    OK(pal_osSemaphoreRelease(completed));
    for (;;) pal_osDelay(10000);
}
static void wait_rtos_idle(void)
{
    ULONGLONG deadline = GetTickCount64() + 3000;
    while (pal_plat_RTOSDestroy() != PAL_SUCCESS && GetTickCount64() < deadline) Sleep(1);
    OK(pal_plat_RTOSDestroy());
}
static void test_threads(void)
{
    palThreadID_t id;
    int32_t available = -1;
    HANDLE thread;
    uint64_t before = pal_osKernelSysTick();
    OK(pal_plat_RTOSInitialize(NULL));
    OK(pal_osDelay(20));
    CHECK(pal_osKernelSysTick() >= before);
    CHECK(pal_osKernelSysTickFrequency() == 1000);
    CHECK(pal_osKernelSysTickMicroSec(1001) == 2);
    OK(pal_osSemaphoreCreate(0, &completed));
    CHECK(pal_osSemaphoreWait(completed, 5, &available) == PAL_ERR_RTOS_TIMEOUT);
    CHECK(available == 0);
    OK(pal_osMutexCreate(&mutex));
    OK(pal_osMutexWait(mutex, 0));
    OK(pal_osMutexWait(mutex, 0));
    OK(pal_osThreadCreateWithAlloc(mutex_worker, NULL, PAL_osPriorityNormal, 4096, NULL, &id));
    OK(pal_osSemaphoreWait(completed, 2000, NULL));
    CHECK(id == observed_id);
    OK(pal_osMutexRelease(mutex));
    OK(pal_osMutexRelease(mutex));
    OK(pal_osMutexDelete(&mutex));
    CHECK(mutex == 0);
    for (int i = 0; i < 4; ++i) OK(pal_osThreadCreateWithAlloc(atomic_worker, NULL, PAL_osPriorityNormal, 4096, NULL, &id));
    for (int i = 0; i < 4; ++i) OK(pal_osSemaphoreWait(completed, 3000, NULL));
    CHECK(total == 40000);
    OK(pal_osThreadCreateWithAlloc(cancellable_worker, NULL, PAL_osPriorityNormal, 4096, NULL, &id));
    OK(pal_osSemaphoreWait(completed, 2000, NULL));
    thread = OpenThread(SYNCHRONIZE, FALSE, (DWORD)id);
    CHECK(thread != NULL);
    OK(pal_osThreadTerminate(&id));
    CHECK(id == 0);
    CHECK(WaitForSingleObject(thread, 2000) == WAIT_OBJECT_0);
    CloseHandle(thread);
    OK(pal_osSemaphoreDelete(&completed));
    wait_rtos_idle();
    puts("PASS threads, recursion, timeout, cancellation, atomics");
}

static palTimerID_t self_timer;
static volatile LONG timer_calls;
static void timer_callback(const void *argument)
{
    InterlockedIncrement(&timer_calls);
    OK(pal_osSemaphoreRelease(*(palSemaphoreID_t *)argument));
}
static void delete_timer_callback(const void *argument)
{
    OK(pal_osTimerDelete(&self_timer));
    OK(pal_osSemaphoreRelease(*(palSemaphoreID_t *)argument));
}
static void test_timers(void)
{
    palTimerID_t timer;
    LONG stopped;
    OK(pal_osSemaphoreCreate(0, &completed));
    OK(pal_osTimerCreate(timer_callback, &completed, palOsTimerOnce, &timer));
    CHECK(pal_osTimerStart(timer, 0) == PAL_ERR_RTOS_VALUE);
    /* Short one-shots cross GetTickCount64's coarse tick boundaries. A native
     * timer wake before the recorded deadline must never lose the callback. */
    for (uint32_t interval = 1; interval <= 32; ++interval) {
        OK(pal_osTimerStart(timer, interval % 16 + 1));
        OK(pal_osSemaphoreWait(completed, 2000, NULL));
    }
    OK(pal_osTimerStart(timer, 15));
    OK(pal_osSemaphoreWait(completed, 2000, NULL));
    CHECK(pal_osSemaphoreWait(completed, 45, NULL) == PAL_ERR_RTOS_TIMEOUT);
    OK(pal_osTimerStart(timer, 500));
    OK(pal_osTimerStart(timer, 10));
    OK(pal_osSemaphoreWait(completed, 2000, NULL));
    OK(pal_osTimerDelete(&timer));
    OK(pal_osTimerCreate(timer_callback, &completed, palOsTimerPeriodic, &timer));
    OK(pal_osTimerStart(timer, 10));
    for (int i = 0; i < 3; ++i) OK(pal_osSemaphoreWait(completed, 2000, NULL));
    OK(pal_osTimerStop(timer));
    Sleep(30); /* An already dispatched callback may finish after stop. */
    stopped = timer_calls;
    Sleep(40);
    CHECK(timer_calls == stopped);
    OK(pal_osTimerDelete(&timer));
    while (pal_osSemaphoreWait(completed, 0, NULL) == PAL_SUCCESS) {}
    OK(pal_osTimerCreate(delete_timer_callback, &completed, palOsTimerOnce, &self_timer));
    OK(pal_osTimerStart(self_timer, 5));
    OK(pal_osSemaphoreWait(completed, 2000, NULL));
    CHECK(self_timer == 0);
    wait_rtos_idle();
    OK(pal_osSemaphoreDelete(&completed));
    puts("PASS one-shot, periodic, restart, stop and callback self-delete timers");
}

static void test_files(void)
{
    char root[64], src[80], dst[80], nested[100], file[128], copy[128], child[128];
    const unsigned char payload[] = {0, 10, 13, 26, 255, 42};
    unsigned char buffer[32];
    palFileDescriptor_t fd, duplicate;
    off_t offset;
    size_t count;
    LARGE_INTEGER large;
    snprintf(root, sizeof(root), "pal-test-%lu-%llu", GetCurrentProcessId(), GetTickCount64());
    snprintf(src, sizeof(src), "%s/src", root);
    snprintf(dst, sizeof(dst), "%s/dst", root);
    snprintf(nested, sizeof(nested), "%s/child", src);
    snprintf(file, sizeof(file), "%s/caf\xc3\xa9.bin", src);
    snprintf(copy, sizeof(copy), "%s/caf\xc3\xa9.bin", dst);
    snprintf(child, sizeof(child), "%s/keep.bin", nested);
    OK(pal_fsMkDir(root)); OK(pal_fsMkDir(src)); OK(pal_fsMkDir(dst)); OK(pal_fsMkDir(nested));
    OK(pal_fsFopen(child, PAL_FS_FLAG_READWRITEEXCLUSIVE, &fd)); OK(pal_fsFclose(&fd));
    OK(pal_fsFopen(file, PAL_FS_FLAG_READWRITEEXCLUSIVE, &fd));
    OK(pal_fsFwrite(&fd, payload, sizeof(payload), &count)); CHECK(count == sizeof(payload));
    OK(pal_fsFtell(&fd, &offset)); CHECK(offset == sizeof(payload));
    OK(pal_fsFseek(&fd, 0, PAL_FS_OFFSET_SEEKSET));
    OK(pal_fsFread(&fd, buffer, sizeof(buffer), &count));
    CHECK(count == sizeof(payload) && !memcmp(payload, buffer, count));
    OK(pal_fsFread(&fd, buffer, sizeof(buffer), &count)); CHECK(count == 0);
    CHECK(pal_fsFseek(&fd, -1, PAL_FS_OFFSET_SEEKSET) == PAL_ERR_FS_OFFSET_ERROR);
    large.QuadPart = INT64_C(0x80000000);
    CHECK(SetFilePointerEx((HANDLE)fd, large, NULL, FILE_BEGIN));
    CHECK(pal_fsFtell(&fd, &offset) == PAL_ERR_FS_OFFSET_ERROR);
    OK(pal_fsFclose(&fd)); CHECK(fd == 0);
    CHECK(pal_fsFopen(file, PAL_FS_FLAG_READWRITEEXCLUSIVE, &duplicate) == PAL_ERR_FS_NAME_ALREADY_EXIST);
    CHECK(duplicate == 0);
    OK(pal_fsCpFolder(src, dst));
    OK(pal_fsCpFolder(src, dst)); /* An existing destination file is replaced. */
    OK(pal_fsFopen(copy, PAL_FS_FLAG_READONLY, &fd));
    OK(pal_fsFread(&fd, buffer, sizeof(buffer), &count)); CHECK(count == sizeof(payload) && !memcmp(payload, buffer, count));
    CHECK(pal_fsFwrite(&fd, payload, sizeof(payload), &count) == PAL_ERR_FS_ACCESS_DENIED);
    OK(pal_fsFclose(&fd));
    OK(pal_fsRmFiles(src)); /* Flat removal must preserve nested data. */
    OK(pal_fsFopen(child, PAL_FS_FLAG_READONLY, &fd)); OK(pal_fsFclose(&fd));
    CHECK(pal_fsRmDir(src) == PAL_ERR_FS_DIR_NOT_EMPTY);
    OK(pal_fsUnlink(child)); OK(pal_fsRmDir(nested)); OK(pal_fsRmDir(src));
    OK(pal_fsRmFiles(dst)); OK(pal_fsRmDir(dst)); OK(pal_fsRmDir(root));
    CHECK(pal_plat_fsFormat(PAL_FS_PARTITION_PRIMARY) == PAL_ERR_NOT_SUPPORTED);
    CHECK(pal_plat_fsMkdir("bad-\xff") == PAL_ERR_FS_INVALID_FILE_NAME);
    puts("PASS UTF-8 paths, binary files, exclusive create, EOF, offsets, flat copy/delete");
}

static void notify_socket(void *event) { CHECK(SetEvent((HANDLE)event)); }
static SOCKET native_listener(int family, int type, palSocketAddress_t *pal, int *native_length)
{
    SOCKET result = socket(family, type, 0);
    struct sockaddr_storage address = {0};
    CHECK(result != INVALID_SOCKET);
    if (family == AF_INET) {
        struct sockaddr_in *v4 = (struct sockaddr_in *)&address;
        v4->sin_family = AF_INET; v4->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        *native_length = sizeof(*v4);
    } else {
        struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)&address;
        v6->sin6_family = AF_INET6; v6->sin6_addr = in6addr_loopback;
        *native_length = sizeof(*v6);
    }
    CHECK(bind(result, (struct sockaddr *)&address, *native_length) == 0);
    CHECK(getsockname(result, (struct sockaddr *)&address, native_length) == 0);
    memset(pal, 0, sizeof(*pal));
    memcpy(pal, &address, (size_t)*native_length);
    pal->addressType = family == AF_INET ? PAL_AF_INET : PAL_AF_INET6;
    return result;
}
static void wait_readable(SOCKET socket)
{
    fd_set read;
    struct timeval timeout = {3, 0};
    FD_ZERO(&read); FD_SET(socket, &read);
    CHECK(select(0, &read, NULL, NULL, &timeout) == 1);
}
static void test_network_family(int family)
{
    const char payload[] = "PAL loopback";
    char buffer[64];
    struct sockaddr_storage source;
    int length, source_length = sizeof(source), one = 1;
    palSocketAddress_t address, from, local;
    palSocketLength_t from_length = sizeof(from);
    size_t count = 0;
    palStatus_t status;
    palSocket_t client;
    palSocketDomain_t domain = family == AF_INET ? PAL_AF_INET : PAL_AF_INET6;
    HANDLE event = CreateEventW(NULL, FALSE, FALSE, NULL);
    SOCKET server = native_listener(family, SOCK_DGRAM, &address, &length), peer;
    ULONGLONG deadline;
    bool nonblocking = false;
    CHECK(event != NULL);
    OK(pal_asynchronousSocketWithArgument(domain, PAL_SOCK_DGRAM, true, 0, notify_socket, event, &client));
    local = address;
    OK(pal_setSockAddrPort(&local, 0));
    OK(pal_bind(client, &local, (palSocketLength_t)length));
    OK(pal_isNonBlocking(client, &nonblocking)); CHECK(nonblocking);
    OK(pal_setSocketOptions(client, PAL_SO_REUSEADDR, &one, sizeof(one)));
    CHECK(pal_receiveFrom(client, buffer, sizeof(buffer), NULL, NULL, &count) == PAL_ERR_SOCKET_WOULD_BLOCK);
    OK(pal_sendTo(client, payload, sizeof(payload), &address, (palSocketLength_t)length, &count)); CHECK(count == sizeof(payload));
    wait_readable(server);
    CHECK(recvfrom(server, buffer, sizeof(buffer), 0, (struct sockaddr *)&source, &source_length) == sizeof(payload));
    CHECK(sendto(server, payload, sizeof(payload), 0, (struct sockaddr *)&source, source_length) == sizeof(payload));
    deadline = GetTickCount64() + 3000;
    do {
        status = pal_receiveFrom(client, buffer, sizeof(buffer), &from, &from_length, &count);
        if (status == PAL_ERR_SOCKET_WOULD_BLOCK) WaitForSingleObject(event, 50);
    } while (status == PAL_ERR_SOCKET_WOULD_BLOCK && GetTickCount64() < deadline);
    OK(status); CHECK(count == sizeof(payload) && !memcmp(buffer, payload, count));
    CHECK(from.addressType == domain);
    OK(pal_close(&client)); CHECK(client == NULL); closesocket(server);

    server = native_listener(family, SOCK_STREAM, &address, &length);
    CHECK(listen(server, 1) == 0);
    OK(pal_asynchronousSocketWithArgument(domain, PAL_SOCK_STREAM, true, 0, notify_socket, event, &client));
    status = pal_connect(client, &address, (palSocketLength_t)length);
    CHECK(status == PAL_SUCCESS || status == PAL_ERR_SOCKET_IN_PROGRES);
    wait_readable(server); peer = accept(server, NULL, NULL); CHECK(peer != INVALID_SOCKET);
    deadline = GetTickCount64() + 3000;
    do {
        status = pal_send(client, payload, sizeof(payload), &count);
        if (status == PAL_ERR_SOCKET_WOULD_BLOCK) WaitForSingleObject(event, 50);
    } while (status == PAL_ERR_SOCKET_WOULD_BLOCK && GetTickCount64() < deadline);
    OK(status); CHECK(count == sizeof(payload));
    wait_readable(peer); CHECK(recv(peer, buffer, sizeof(buffer), 0) == sizeof(payload));
    CHECK(send(peer, payload, sizeof(payload), 0) == sizeof(payload));
    deadline = GetTickCount64() + 3000;
    do {
        status = pal_recv(client, buffer, sizeof(buffer), &count);
        if (status == PAL_ERR_SOCKET_WOULD_BLOCK) WaitForSingleObject(event, 50);
    } while (status == PAL_ERR_SOCKET_WOULD_BLOCK && GetTickCount64() < deadline);
    OK(status); CHECK(count == sizeof(payload) && !memcmp(buffer, payload, count));
    closesocket(peer);
    deadline = GetTickCount64() + 3000;
    do {
        status = pal_recv(client, buffer, sizeof(buffer), &count);
        if (status == PAL_ERR_SOCKET_WOULD_BLOCK) WaitForSingleObject(event, 50);
    } while (status == PAL_ERR_SOCKET_WOULD_BLOCK && GetTickCount64() < deadline);
    CHECK(status == PAL_ERR_SOCKET_CONNECTION_CLOSED);
    OK(pal_close(&client)); closesocket(server); CloseHandle(event);
    puts(family == AF_INET ? "PASS IPv4 UDP/TCP and asynchronous callbacks" : "PASS IPv6 UDP/TCP and address-family translation");
}

static void dns_callback(const char *name, palSocketAddress_t *address, palSocketLength_t *length,
    palStatus_t status, void *argument)
{
    (void)name;
    OK(status); CHECK(*length && (address->addressType == PAL_AF_INET || address->addressType == PAL_AF_INET6));
    CHECK(SetEvent(argument));
}
static void test_dns_entropy(void)
{
    unsigned char a[64], b[64];
    size_t actual;
    palSocketAddress_t address;
    palSocketLength_t length;
    HANDLE done = CreateEventW(NULL, FALSE, FALSE, NULL);
    CHECK(done != NULL);
    OK(pal_getAddressInfoAsync("localhost", &address, &length, dns_callback, done));
    CHECK(WaitForSingleObject(done, 3000) == WAIT_OBJECT_0);
    CloseHandle(done); wait_rtos_idle();
    OK(pal_plat_getRandomBufferFromHW(a, sizeof(a), &actual)); CHECK(actual == sizeof(a));
    OK(pal_plat_getRandomBufferFromHW(b, sizeof(b), &actual)); CHECK(actual == sizeof(b));
    CHECK(memcmp(a, b, sizeof(a)) != 0);
    CHECK(pal_plat_getRandomBufferFromHW(NULL, 1, &actual) == PAL_ERR_INVALID_ARGUMENT);
    CHECK(actual == 0);
    puts("PASS PAL asynchronous localhost DNS and system entropy");
}

typedef struct callback_close_context {
    palSocket_t socket;
    HANDLE done;
} callback_close_context;
static void close_socket_callback(void *argument)
{
    callback_close_context *context = argument;
    char buffer[16];
    size_t received;
    palStatus_t status = pal_receiveFrom(context->socket, buffer, sizeof(buffer), NULL, NULL, &received);
    if (status == PAL_SUCCESS && received) {
        OK(pal_close(&context->socket));
        CHECK(SetEvent(context->done));
    } else CHECK(status == PAL_ERR_SOCKET_WOULD_BLOCK || status == PAL_ERR_SOCKET_INVALID_VALUE);
}
static void test_callback_close(void)
{
    callback_close_context context = {0};
    palSocketAddress_t address;
    struct sockaddr_storage source;
    int length, source_length = sizeof(source);
    size_t sent;
    char buffer[16];
    SOCKET server = native_listener(AF_INET, SOCK_DGRAM, &address, &length);
    context.done = CreateEventW(NULL, FALSE, FALSE, NULL);
    CHECK(context.done != NULL);
    OK(pal_asynchronousSocketWithArgument(PAL_AF_INET, PAL_SOCK_DGRAM, true, 0, close_socket_callback, &context, &context.socket));
    OK(pal_sendTo(context.socket, "request", 8, &address, (palSocketLength_t)length, &sent));
    wait_readable(server);
    CHECK(recvfrom(server, buffer, sizeof(buffer), 0, (struct sockaddr *)&source, &source_length) == 8);
    CHECK(sendto(server, "reply", 6, 0, (struct sockaddr *)&source, source_length) == 6);
    CHECK(WaitForSingleObject(context.done, 3000) == WAIT_OBJECT_0);
    CHECK(context.socket == NULL);
    CloseHandle(context.done); closesocket(server);
    puts("PASS closing a socket from its own callback");
}

static void test_resource_lifecycle(void)
{
    DWORD before, after;
    HANDLE event = CreateEventW(NULL, FALSE, FALSE, NULL);
    palSocket_t socket;
    palTimerID_t timer;
    CHECK(event != NULL);
    CHECK(GetProcessHandleCount(GetCurrentProcess(), &before));
    for (int i = 0; i < 64; ++i) {
        OK(pal_asynchronousSocketWithArgument(PAL_AF_INET, PAL_SOCK_DGRAM, true, 0, notify_socket, event, &socket));
        CHECK(pal_plat_socketsTerminate(NULL) == PAL_ERR_SOCKET_OPERATION_NOT_PERMITTED);
        OK(pal_close(&socket));
        OK(pal_osTimerCreate(timer_callback, &completed, palOsTimerOnce, &timer));
        OK(pal_osTimerStart(timer, 60000));
        OK(pal_osTimerDelete(&timer));
    }
    wait_rtos_idle();
    CHECK(GetProcessHandleCount(GetCurrentProcess(), &after));
    CHECK(after <= before);
    CloseHandle(event);
    puts("PASS repeated socket/timer cleanup without handle growth");
}

static void test_accept(void)
{
    palSocketAddress_t address, peer_address;
    palSocketLength_t peer_length = sizeof(peer_address);
    int length;
    palSocket_t listener, accepted = NULL;
    SOCKET reservation = native_listener(AF_INET, SOCK_STREAM, &address, &length), client;
    struct sockaddr_in native;
    HANDLE ready = CreateEventW(NULL, FALSE, FALSE, NULL);
    palStatus_t status;
    ULONGLONG deadline;
    size_t received;
    char buffer[8];
    CHECK(ready != NULL);
    closesocket(reservation);
    OK(pal_asynchronousSocketWithArgument(PAL_AF_INET, PAL_SOCK_STREAM_SERVER, true, 0, notify_socket, ready, &listener));
    OK(pal_bind(listener, &address, (palSocketLength_t)length));
    OK(pal_listen(listener, 1));
    client = socket(AF_INET, SOCK_STREAM, 0); CHECK(client != INVALID_SOCKET);
    memcpy(&native, &address, sizeof(native)); native.sin_family = AF_INET;
    CHECK(connect(client, (struct sockaddr *)&native, sizeof(native)) == 0);
    deadline = GetTickCount64() + 3000;
    do {
        status = pal_plat_accept(listener, &peer_address, &peer_length, &accepted, notify_socket, ready);
        if (status == PAL_ERR_SOCKET_WOULD_BLOCK) WaitForSingleObject(ready, 50);
    } while (status == PAL_ERR_SOCKET_WOULD_BLOCK && GetTickCount64() < deadline);
    OK(status); CHECK(peer_address.addressType == PAL_AF_INET);
    CHECK(send(client, "accept", 7, 0) == 7);
    deadline = GetTickCount64() + 3000;
    do {
        status = pal_recv(accepted, buffer, sizeof(buffer), &received);
        if (status == PAL_ERR_SOCKET_WOULD_BLOCK) WaitForSingleObject(ready, 50);
    } while (status == PAL_ERR_SOCKET_WOULD_BLOCK && GetTickCount64() < deadline);
    OK(status); CHECK(received == 7 && !memcmp(buffer, "accept", 7));
    OK(pal_close(&accepted)); OK(pal_close(&listener));
    closesocket(client); CloseHandle(ready);
    puts("PASS listen, accept and independent accepted-socket events");
}

int main(void)
{
    uint32_t index;
    test_threads(); test_timers(); test_files();
    OK(pal_plat_socketsInit(NULL));
    OK(pal_registerNetworkInterface("default", &index)); CHECK(index == 0);
    test_network_family(AF_INET); test_network_family(AF_INET6); test_dns_entropy();
    test_callback_close(); test_resource_lifecycle(); test_accept();
    OK(pal_unregisterNetworkInterface(index)); OK(pal_plat_socketsTerminate(NULL));
    wait_rtos_idle();
    puts("All Windows PAL runtime checks passed.");
    return 0;
}
