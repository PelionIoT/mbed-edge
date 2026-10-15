/* SPDX-License-Identifier: Apache-2.0 */
#include <arpa/inet.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "pal.h"
#include "pal_plat_TLS.h"
#include "pal_plat_network.h"
#include "eventOS_event.h"

static void fail(const char *expression, int line)
{
    fprintf(stderr, "TLS test line %d: %s failed\n", line, expression);
    ERR_print_errors_fp(stderr);
    exit(1);
}
#define CHECK(value) do { if (!(value)) fail(#value, __LINE__); } while (0)
#define OK(value) CHECK((value) == PAL_SUCCESS)

/* The transport and certificate checks are real. These two fixtures replace
 * the unused legacy entropy and event-loop hooks in the standalone TLS test. */
extern palStatus_t pal_plat_getRandomBufferFromHW(uint8_t *, size_t, size_t *);
palStatus_t pal_osRandomBuffer(uint8_t *buffer, size_t size)
{
    size_t actual;
    return pal_plat_getRandomBufferFromHW(buffer, size, &actual);
}
void eventOS_cancel(arm_event_storage_t *event) { CHECK(event == NULL); }

static const char payload[] = "OpenSSL via Darwin PAL";
typedef struct server_fixture {
    int listener;
    SSL_CTX *context;
    palSemaphoreID_t go;
    bool reject;
    bool client_auth;
} server_fixture;

static void *server_main(void *argument)
{
    server_fixture *fixture = argument;
    int fd = accept(fixture->listener, NULL, NULL);
    CHECK(fd >= 0);
    struct timeval timeout = {5, 0};
    int enabled = 1;
    CHECK(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
    CHECK(setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0);
    CHECK(setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &enabled, sizeof(enabled)) == 0);
    SSL *tls = SSL_new(fixture->context); CHECK(tls != NULL);
    CHECK(SSL_set_fd(tls, fd) == 1);
    OK(pal_osSemaphoreWait(fixture->go, 5000, NULL));
    int result = SSL_accept(tls);
    if (fixture->reject) {
        CHECK(result <= 0);
        ERR_clear_error();
    } else {
        CHECK(result == 1);
        if (fixture->client_auth) {
            X509 *peer = SSL_get1_peer_certificate(tls);
            CHECK(peer != NULL && SSL_get_verify_result(tls) == X509_V_OK);
            X509_free(peer);
        }
        char buffer[sizeof(payload)];
        size_t received = 0;
        while (received < sizeof(payload)) {
            result = SSL_read(tls, buffer + received, (int)(sizeof(buffer) - received));
            CHECK(result > 0);
            received += (size_t)result;
        }
        CHECK(!memcmp(buffer, payload, sizeof(payload)));
        CHECK(SSL_write(tls, payload, sizeof(payload)) == sizeof(payload));
    }
    SSL_free(tls);
    CHECK(close(fd) == 0);
    return NULL;
}

static void make_certificate(EVP_PKEY **key, X509 **certificate)
{
    *key = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "prime256v1"); CHECK(*key != NULL);
    *certificate = X509_new(); CHECK(*certificate != NULL);
    CHECK(X509_set_version(*certificate, 2) == 1);
    CHECK(ASN1_INTEGER_set(X509_get_serialNumber(*certificate), 1) == 1);
    CHECK(X509_gmtime_adj(X509_getm_notBefore(*certificate), -60) != NULL);
    CHECK(X509_gmtime_adj(X509_getm_notAfter(*certificate), 3600) != NULL);
    CHECK(X509_set_pubkey(*certificate, *key) == 1);
    X509_NAME *name = X509_get_subject_name(*certificate);
    CHECK(X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
        (const unsigned char *)"localhost", -1, -1, 0) == 1);
    CHECK(X509_set_issuer_name(*certificate, name) == 1);
    CHECK(X509_sign(*certificate, *key, EVP_sha256()) > 0);
}

static bool retry(palStatus_t status)
{
    return status == PAL_ERR_TLS_WANT_READ || status == PAL_ERR_TLS_WANT_WRITE;
}
static void notify(void *argument) { OK(pal_osSemaphoreRelease(*(palSemaphoreID_t *)argument)); }

static void test_tls(bool trust_certificate, bool client_auth)
{
    EVP_PKEY *key, *client_key = NULL;
    X509 *certificate, *client_certificate = NULL;
    unsigned char *der = NULL, *client_der = NULL, *private_der = NULL;
    server_fixture fixture = {0};
    make_certificate(&key, &certificate);
    fixture.reject = !trust_certificate;
    fixture.client_auth = client_auth;
    fixture.context = SSL_CTX_new(TLS_server_method()); CHECK(fixture.context != NULL);
    CHECK(SSL_CTX_set_max_proto_version(fixture.context, TLS1_2_VERSION) == 1);
    CHECK(SSL_CTX_set_cipher_list(fixture.context, "ECDHE-ECDSA-AES128-GCM-SHA256") == 1);
    CHECK(SSL_CTX_use_certificate(fixture.context, certificate) == 1);
    CHECK(SSL_CTX_use_PrivateKey(fixture.context, key) == 1);
    if (client_auth) {
        make_certificate(&client_key, &client_certificate);
        CHECK(X509_STORE_add_cert(SSL_CTX_get_cert_store(fixture.context), client_certificate) == 1);
        SSL_CTX_set_verify(fixture.context, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    }
    OK(pal_osSemaphoreCreate(0, &fixture.go));
    fixture.listener = socket(AF_INET, SOCK_STREAM, 0); CHECK(fixture.listener >= 0);
    struct sockaddr_in native = {0};
    native.sin_len = sizeof(native); native.sin_family = AF_INET; native.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    CHECK(bind(fixture.listener, (struct sockaddr *)&native, sizeof(native)) == 0);
    socklen_t native_size = sizeof(native);
    CHECK(getsockname(fixture.listener, (struct sockaddr *)&native, &native_size) == 0);
    CHECK(listen(fixture.listener, 1) == 0);
    palSocketAddress_t address = {0};
    palIpV4Addr_t loopback = {127, 0, 0, 1};
    OK(pal_setSockAddrIPV4Addr(&address, loopback));
    OK(pal_setSockAddrPort(&address, ntohs(native.sin_port)));
    pthread_t worker;
    CHECK(pthread_create(&worker, NULL, server_main, &fixture) == 0);
    palSemaphoreID_t ready;
    OK(pal_osSemaphoreCreate(0, &ready));
    palSocket_t client;
    OK(pal_asynchronousSocketWithArgument(PAL_AF_INET, PAL_SOCK_STREAM, true, PAL_NET_DEFAULT_INTERFACE, notify, &ready, &client));
    palStatus_t status = pal_connect(client, &address, sizeof(address));
    if (status == PAL_ERR_SOCKET_IN_PROGRES) OK(pal_osSemaphoreWait(ready, 5000, NULL));
    CHECK(status == PAL_SUCCESS || status == PAL_ERR_SOCKET_IN_PROGRES);
    palTLSConfHandle_t configuration = 0;
    palTLSHandle_t tls = 0;
    OK(pal_plat_initTLSConf(&configuration, PAL_TLS_MODE, PAL_TLS_IS_CLIENT));
    OK(pal_plat_setCipherSuites(configuration, PAL_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256));
    OK(pal_plat_setAuthenticationMode(configuration, PAL_TLS_VERIFY_REQUIRED));
    if (trust_certificate) {
        int length = i2d_X509(certificate, &der); CHECK(length > 0);
        palX509_t ca = {.buffer = der, .size = (uint32_t)length};
        OK(pal_plat_setCAChain(configuration, &ca, NULL));
    }
    if (client_auth) {
        int length = i2d_X509(client_certificate, &client_der); CHECK(length > 0);
        palX509_t own = {.buffer = client_der, .size = (uint32_t)length};
        length = i2d_PrivateKey(client_key, &private_der); CHECK(length > 0);
        palPrivateKey_t private_key = {.buffer = private_der, .size = (uint32_t)length};
        OK(pal_plat_setOwnCertChain(configuration, &own));
        OK(pal_plat_setOwnPrivateKey(configuration, &private_key));
    }
    OK(pal_plat_initTLS(configuration, &tls));
    OK(pal_plat_sslSetup(tls, configuration));
    palTLSSocket_t transport = {0};
    transport.socket = client; transport.transportationMode = PAL_TLS_MODE;
    OK(pal_plat_tlsSetSocket(configuration, &transport));
    uint64_t server_time;
    status = pal_plat_handShake(tls, &server_time);
    CHECK(retry(status));
    OK(pal_osSemaphoreRelease(fixture.go));
    uint64_t deadline = pal_osKernelSysTick() + 5000000;
    while (retry(status) && pal_osKernelSysTick() < deadline) {
        pal_osSemaphoreWait(ready, 10, NULL);
        status = pal_plat_handShake(tls, &server_time);
    }
    if (trust_certificate) {
        OK(status);
        int32_t verification;
        OK(pal_plat_sslGetVerifyResultExtended(tls, &verification)); CHECK(verification == 0);
        uint32_t transferred = 0;
        OK(pal_plat_sslWrite(tls, payload, sizeof(payload), &transferred)); CHECK(transferred == sizeof(payload));
        char buffer[sizeof(payload)];
        deadline = pal_osKernelSysTick() + 5000000;
        do {
            status = pal_plat_sslRead(tls, buffer, sizeof(buffer), &transferred);
            if (retry(status)) pal_osSemaphoreWait(ready, 10, NULL);
        } while (retry(status) && pal_osKernelSysTick() < deadline);
        OK(status); CHECK(transferred == sizeof(payload) && !memcmp(buffer, payload, sizeof(payload)));
    } else CHECK(status != PAL_SUCCESS && !retry(status));
    CHECK(pthread_join(worker, NULL) == 0);
    OK(pal_plat_freeTLS(&tls)); OK(pal_plat_tlsConfigurationFree(&configuration));
    bool nonblocking;
    OK(pal_isNonBlocking(client, &nonblocking)); CHECK(nonblocking);
    OK(pal_close(&client));
    OK(pal_osSemaphoreDelete(&ready)); OK(pal_osSemaphoreDelete(&fixture.go));
    CHECK(close(fixture.listener) == 0);
    OPENSSL_free(der); X509_free(certificate); EVP_PKEY_free(key); SSL_CTX_free(fixture.context);
    OPENSSL_free(client_der); OPENSSL_free(private_der); X509_free(client_certificate); EVP_PKEY_free(client_key);
}

int main(void)
{
    puts(OpenSSL_version(OPENSSL_VERSION));
    OK(pal_plat_socketsInit(NULL)); OK(pal_plat_initTLSLibrary());
    test_tls(true, false); test_tls(false, false); test_tls(true, true);
    OK(pal_plat_cleanupTLS()); OK(pal_plat_socketsTerminate(NULL));
    puts("macOS PAL verified TLS, untrusted certificate rejection and mutual authentication passed");
    return 0;
}
