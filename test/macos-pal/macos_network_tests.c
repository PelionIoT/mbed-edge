/* SPDX-License-Identifier: Apache-2.0 */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include "pal.h"
#include "pal_plat_network.h"
#include "pal_plat_rtos.h"

#define CHECK(expression) do { if (!(expression)) { \
    fprintf(stderr, "%s:%d: %s failed (errno=%d)\n", __FILE__, __LINE__, #expression, errno); \
    exit(1); } } while (0)
#define OK(expression) CHECK((expression) == PAL_SUCCESS)

typedef struct socket_state {
    palSocket_t socket;
    palSemaphoreID_t changed;
    atomic_bool closed;
    atomic_int late_callbacks;
} socket_state;

static void socket_changed(void *argument)
{
    socket_state *state = argument;
    if (atomic_load(&state->closed)) atomic_fetch_add(&state->late_callbacks, 1);
    OK(pal_osSemaphoreRelease(state->changed));
}

static int native_listener(int family, int type, palSocketAddress_t *address)
{
    int fd = socket(family, type, 0);
    CHECK(fd >= 0);
    struct timeval timeout = {2, 0};
    CHECK(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
    if (family == AF_INET) {
        struct sockaddr_in local = {0};
        local.sin_len = sizeof(local);
        local.sin_family = family;
        local.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        CHECK(bind(fd, (struct sockaddr *)&local, sizeof(local)) == 0);
        socklen_t size = sizeof(local);
        CHECK(getsockname(fd, (struct sockaddr *)&local, &size) == 0);
        palIpV4Addr_t loopback = {127, 0, 0, 1};
        OK(pal_setSockAddrIPV4Addr(address, loopback));
        OK(pal_setSockAddrPort(address, ntohs(local.sin_port)));
    } else {
        struct sockaddr_in6 local = {0};
        local.sin6_len = sizeof(local);
        local.sin6_family = family;
        local.sin6_addr = in6addr_loopback;
        CHECK(bind(fd, (struct sockaddr *)&local, sizeof(local)) == 0);
        socklen_t size = sizeof(local);
        CHECK(getsockname(fd, (struct sockaddr *)&local, &size) == 0);
        palIpV6Addr_t loopback = {0}; loopback[15] = 1;
        OK(pal_setSockAddrIPV6Addr(address, loopback));
        OK(pal_setSockAddrPort(address, ntohs(local.sin6_port)));
    }
    return fd;
}

static void socket_open(socket_state *state, palSocketDomain_t domain, palSocketType_t type)
{
    memset(state, 0, sizeof(*state));
    OK(pal_osSemaphoreCreate(0, &state->changed));
    OK(pal_asynchronousSocketWithArgument(domain, type, true, PAL_NET_DEFAULT_INTERFACE, socket_changed, state, &state->socket));
    bool nonblocking = false;
    OK(pal_isNonBlocking(state->socket, &nonblocking)); CHECK(nonblocking);
}

static void socket_finish(socket_state *state)
{
    OK(pal_close(&state->socket));
    atomic_store(&state->closed, true);
    OK(pal_osDelay(5));
    CHECK(atomic_load(&state->late_callbacks) == 0);
    OK(pal_osSemaphoreDelete(&state->changed));
}

static void test_udp(int family)
{
    palSocketAddress_t destination = {0};
    int server = native_listener(family, SOCK_DGRAM, &destination);
    socket_state state;
    socket_open(&state, family == AF_INET ? PAL_AF_INET : PAL_AF_INET6, PAL_SOCK_DGRAM);
    const char payload[] = "native Darwin UDP";
    size_t count = 0;
    OK(pal_sendTo(state.socket, payload, sizeof(payload), &destination, sizeof(destination), &count));
    CHECK(count == sizeof(payload));
    struct sockaddr_storage peer;
    socklen_t peer_size = sizeof(peer);
    char buffer[100];
    CHECK(recvfrom(server, buffer, sizeof(buffer), 0, (struct sockaddr *)&peer, &peer_size) == sizeof(payload));
    CHECK(!memcmp(buffer, payload, sizeof(payload)));
    CHECK(sendto(server, payload, sizeof(payload), 0, (struct sockaddr *)&peer, peer_size) == sizeof(payload));
    palSocketAddress_t received = {0};
    palSocketLength_t received_size = sizeof(received);
    palStatus_t status;
    uint64_t deadline = pal_osKernelSysTick() + 2000000;
    do {
        status = pal_receiveFrom(state.socket, buffer, sizeof(buffer), &received, &received_size, &count);
        if (status == PAL_ERR_SOCKET_WOULD_BLOCK) pal_osSemaphoreWait(state.changed, 100, NULL);
    } while (status == PAL_ERR_SOCKET_WOULD_BLOCK && pal_osKernelSysTick() < deadline);
    OK(status); CHECK(count == sizeof(payload) && !memcmp(buffer, payload, count));
    CHECK(received.addressType == destination.addressType);
    uint16_t expected_port, received_port;
    OK(pal_getSockAddrPort(&destination, &expected_port));
    OK(pal_getSockAddrPort(&received, &received_port)); CHECK(received_port == expected_port);
    socket_finish(&state);
    CHECK(close(server) == 0);
}

static void *echo_worker(void *argument)
{
    int server = *(int *)argument;
    int peer = accept(server, NULL, NULL);
    CHECK(peer >= 0);
    char buffer[100];
    ssize_t count = recv(peer, buffer, sizeof(buffer), 0);
    CHECK(count > 0);
    CHECK(send(peer, buffer, (size_t)count, 0) == count);
    CHECK(close(peer) == 0);
    return NULL;
}

static void test_tcp(int family)
{
    palSocketAddress_t destination = {0};
    int server = native_listener(family, SOCK_STREAM, &destination);
    CHECK(listen(server, 1) == 0);
    pthread_t echo;
    CHECK(pthread_create(&echo, NULL, echo_worker, &server) == 0);
    socket_state state;
    socket_open(&state, family == AF_INET ? PAL_AF_INET : PAL_AF_INET6, PAL_SOCK_STREAM);
    palStatus_t status = pal_connect(state.socket, &destination, sizeof(destination));
    CHECK(status == PAL_SUCCESS || status == PAL_ERR_SOCKET_IN_PROGRES);
    if (status == PAL_ERR_SOCKET_IN_PROGRES) OK(pal_osSemaphoreWait(state.changed, 2000, NULL));
    const char payload[] = "native Darwin TCP";
    size_t count = 0;
    uint64_t deadline = pal_osKernelSysTick() + 2000000;
    do {
        status = pal_send(state.socket, payload, sizeof(payload), &count);
        if (status == PAL_ERR_SOCKET_WOULD_BLOCK) pal_osSemaphoreWait(state.changed, 100, NULL);
    } while (status == PAL_ERR_SOCKET_WOULD_BLOCK && pal_osKernelSysTick() < deadline);
    OK(status); CHECK(count == sizeof(payload));
    char buffer[100];
    do {
        status = pal_recv(state.socket, buffer, sizeof(buffer), &count);
        if (status == PAL_ERR_SOCKET_WOULD_BLOCK) pal_osSemaphoreWait(state.changed, 100, NULL);
    } while (status == PAL_ERR_SOCKET_WOULD_BLOCK && pal_osKernelSysTick() < deadline);
    OK(status); CHECK(count == sizeof(payload) && !memcmp(buffer, payload, count));
    CHECK(pthread_join(echo, NULL) == 0);
    socket_finish(&state);
    CHECK(close(server) == 0);
}

static void test_interfaces_and_dns(void)
{
    uint32_t index, count;
    OK(pal_registerNetworkInterface("lo0", &index));
    palNetInterfaceInfo_t info;
    OK(pal_getNetInterfaceInfo(index, &info)); CHECK(!strcmp(info.interfaceName, "lo0"));
    OK(pal_getNumberOfNetInterfaces(&count)); CHECK(count == 1);
    OK(pal_unregisterNetworkInterface(index));
    OK(pal_registerNetworkInterface("default", &index));
    /* Route selection is queried on demand; an offline host may have no route. */
    palStatus_t status = pal_getNetInterfaceInfo(index, &info);
    CHECK(status == PAL_SUCCESS || status == PAL_ERR_GENERIC_FAILURE);
    OK(pal_unregisterNetworkInterface(index));
    palSocketAddress_t address = {0};
    palSocketLength_t size = sizeof(address);
    OK(pal_getAddressInfo("127.0.0.1", &address, &size)); CHECK(address.addressType == PAL_AF_INET);
    OK(pal_getAddressInfo("::1", &address, &size)); CHECK(address.addressType == PAL_AF_INET6);
    CHECK(pal_getAddressInfo("", &address, &size) == PAL_ERR_SOCKET_DNS_ERROR);
}

typedef struct close_state {
    palSocket_t socket;
    palSemaphoreID_t entered;
    palSemaphoreID_t release;
    palSemaphoreID_t closing;
    atomic_bool closed;
} close_state;

static void blocking_socket_callback(void *argument)
{
    close_state *state = argument;
    OK(pal_osSemaphoreRelease(state->entered));
    OK(pal_osSemaphoreWait(state->release, 2000, NULL));
    CHECK(fcntl((int)(intptr_t)state->socket, F_GETFD) >= 0);
}

static void *close_socket_worker(void *argument)
{
    close_state *state = argument;
    OK(pal_osSemaphoreRelease(state->closing));
    OK(pal_close(&state->socket));
    atomic_store(&state->closed, true);
    return NULL;
}

static void self_close_socket_callback(void *argument)
{
    close_state *state = argument;
    OK(pal_close(&state->socket));
    OK(pal_osSemaphoreRelease(state->entered));
}

static void test_close_during_callback(void)
{
    close_state state = {0};
    OK(pal_osSemaphoreCreate(0, &state.entered));
    OK(pal_osSemaphoreCreate(0, &state.release));
    OK(pal_osSemaphoreCreate(0, &state.closing));
    OK(pal_asynchronousSocketWithArgument(PAL_AF_INET, PAL_SOCK_DGRAM, true, PAL_NET_DEFAULT_INTERFACE,
        blocking_socket_callback, &state, &state.socket));
    OK(pal_osSemaphoreWait(state.entered, 2000, NULL));
    int original = (int)(intptr_t)state.socket;
    pthread_t closer;
    CHECK(pthread_create(&closer, NULL, close_socket_worker, &state) == 0);
    OK(pal_osSemaphoreWait(state.closing, 2000, NULL));
    OK(pal_osDelay(20)); CHECK(!atomic_load(&state.closed));
    int temporary[32];
    for (size_t i = 0; i < sizeof(temporary) / sizeof(temporary[0]); ++i) {
        temporary[i] = socket(AF_INET, SOCK_DGRAM, 0);
        CHECK(temporary[i] >= 0 && temporary[i] != original);
    }
    OK(pal_osSemaphoreRelease(state.release));
    CHECK(pthread_join(closer, NULL) == 0); CHECK(atomic_load(&state.closed));
    for (size_t i = 0; i < sizeof(temporary) / sizeof(temporary[0]); ++i) CHECK(close(temporary[i]) == 0);
    OK(pal_asynchronousSocketWithArgument(PAL_AF_INET, PAL_SOCK_DGRAM, true, PAL_NET_DEFAULT_INTERFACE,
        self_close_socket_callback, &state, &state.socket));
    OK(pal_osSemaphoreWait(state.entered, 2000, NULL));
    CHECK(state.socket == (palSocket_t)(intptr_t)-1);
    OK(pal_osSemaphoreDelete(&state.entered));
    OK(pal_osSemaphoreDelete(&state.release));
    OK(pal_osSemaphoreDelete(&state.closing));
}

int main(void)
{
    OK(pal_plat_RTOSInitialize(NULL));
    for (int round = 0; round < 5; ++round) {
        OK(pal_plat_socketsInit(NULL));
        test_interfaces_and_dns();
        test_udp(AF_INET); test_udp(AF_INET6);
        test_tcp(AF_INET); test_tcp(AF_INET6);
        test_close_during_callback();
        for (int i = 0; i < 50; ++i) {
            socket_state state;
            socket_open(&state, PAL_AF_INET, PAL_SOCK_DGRAM);
            socket_finish(&state);
        }
        OK(pal_plat_socketsTerminate(NULL));
    }
    OK(pal_plat_RTOSDestroy());
    puts("macOS PAL IPv4/IPv6 TCP, UDP, DNS, interfaces and descriptor reuse passed");
    return 0;
}
