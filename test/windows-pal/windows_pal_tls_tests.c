/* SPDX-License-Identifier: Apache-2.0 */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <process.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "pal.h"
#include "pal_plat_TLS.h"
#include "pal_plat_network.h"
#include "eventOS_event.h"

static void fail(const char *expression, int line)
{
    unsigned long error;
    char message[256];
    fprintf(stderr, "TLS test line %d: %s failed\n", line, expression);
    while ((error = ERR_get_error()) != 0) {
        ERR_error_string_n(error, message, sizeof(message));
        fprintf(stderr, "%s\n", message);
    }
    exit(1);
}
#define CHECK(value) do { if (!(value)) fail(#value, __LINE__); } while (0)
#define OK(value) CHECK((value) == PAL_SUCCESS)

/* Standalone fixtures for the unused legacy entropy/event-loop hooks. The
 * transport, TLS implementation, certificate validation and OpenSSL are real.
 * Generic DRBG, storage and the application event loop are outside this test. */
extern palStatus_t pal_plat_getRandomBufferFromHW(uint8_t *, size_t, size_t *);
palStatus_t pal_osRandomBuffer(uint8_t *buffer, size_t size)
{
    size_t actual;
    return pal_plat_getRandomBufferFromHW(buffer, size, &actual);
}
void eventOS_cancel(arm_event_storage_t *event) { CHECK(event == NULL); }

static const char payload[] = "OpenSSL via Windows PAL";
typedef struct server_fixture {
    SOCKET listener;
    SSL_CTX *context;
    HANDLE go;
    bool reject;
    bool client_auth;
} server_fixture;

static unsigned __stdcall server_main(void *argument)
{
    server_fixture *fixture = argument;
    SOCKET socket = accept(fixture->listener, NULL, NULL);
    SSL *tls;
    char buffer[sizeof(payload)];
    DWORD timeout = 5000;
    int received = 0, result;
    CHECK(socket != INVALID_SOCKET && socket <= INT_MAX);
    CHECK(setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) == 0);
    CHECK(setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout)) == 0);
    tls = SSL_new(fixture->context); CHECK(tls != NULL);
    CHECK(SSL_set_fd(tls, (int)socket) == 1); /* Native test-server socket only. */
    CHECK(WaitForSingleObject(fixture->go, 5000) == WAIT_OBJECT_0);
    result = SSL_accept(tls);
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
        while (received < (int)sizeof(payload)) {
            result = SSL_read(tls, buffer + received, (int)sizeof(buffer) - received);
            CHECK(result > 0);
            received += result;
        }
        CHECK(memcmp(buffer, payload, sizeof(payload)) == 0);
        CHECK(SSL_write(tls, payload, sizeof(payload)) == sizeof(payload));
    }
    SSL_free(tls);
    closesocket(socket);
    return 0;
}

static void make_certificate(EVP_PKEY **key, X509 **certificate)
{
    X509_NAME *name;
    *key = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "prime256v1"); CHECK(*key != NULL);
    *certificate = X509_new(); CHECK(*certificate != NULL);
    CHECK(X509_set_version(*certificate, 2) == 1);
    CHECK(ASN1_INTEGER_set(X509_get_serialNumber(*certificate), 1) == 1);
    CHECK(X509_gmtime_adj(X509_getm_notBefore(*certificate), -60) != NULL);
    CHECK(X509_gmtime_adj(X509_getm_notAfter(*certificate), 3600) != NULL);
    CHECK(X509_set_pubkey(*certificate, *key) == 1);
    name = X509_get_subject_name(*certificate);
    CHECK(X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
        (const unsigned char *)"localhost", -1, -1, 0) == 1);
    CHECK(X509_set_issuer_name(*certificate, name) == 1);
    CHECK(X509_sign(*certificate, *key, EVP_sha256()) > 0);
}

static bool retry(palStatus_t status)
{
    return status == PAL_ERR_TLS_WANT_READ || status == PAL_ERR_TLS_WANT_WRITE;
}
static void notify(void *event) { CHECK(SetEvent((HANDLE)event)); }

static void test_tls(bool trust_certificate, bool client_auth)
{
    EVP_PKEY *key;
    X509 *certificate;
    EVP_PKEY *client_key = NULL;
    X509 *client_certificate = NULL;
    unsigned char *der = NULL;
    unsigned char *client_der = NULL, *private_der = NULL;
    int der_length, address_length;
    struct sockaddr_in native = {0};
    palSocketAddress_t address = {0};
    palSocket_t client;
    palTLSSocket_t transport = {0};
    palTLSConfHandle_t configuration = 0;
    palTLSHandle_t tls = 0;
    palStatus_t status;
    palX509_t ca;
    server_fixture fixture = {0};
    HANDLE worker, ready;
    ULONGLONG deadline;
    uint64_t server_time;
    uint32_t transferred;
    int32_t verification;
    char buffer[sizeof(payload)];

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
    fixture.go = CreateEventW(NULL, TRUE, FALSE, NULL); CHECK(fixture.go != NULL);
    fixture.listener = socket(AF_INET, SOCK_STREAM, 0); CHECK(fixture.listener != INVALID_SOCKET);
    native.sin_family = AF_INET; native.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    CHECK(bind(fixture.listener, (struct sockaddr *)&native, sizeof(native)) == 0);
    address_length = sizeof(native);
    CHECK(getsockname(fixture.listener, (struct sockaddr *)&native, &address_length) == 0);
    CHECK(listen(fixture.listener, 1) == 0);
    memcpy(&address, &native, sizeof(native)); address.addressType = PAL_AF_INET;
    worker = (HANDLE)_beginthreadex(NULL, 0, server_main, &fixture, 0, NULL); CHECK(worker != NULL);
    ready = CreateEventW(NULL, FALSE, FALSE, NULL); CHECK(ready != NULL);
    OK(pal_asynchronousSocketWithArgument(PAL_AF_INET, PAL_SOCK_STREAM, true, 0, notify, ready, &client));
    deadline = GetTickCount64() + 5000;
    do {
        status = pal_connect(client, &address, (palSocketLength_t)address_length);
        if (status == PAL_ERR_SOCKET_IN_PROGRES || status == PAL_ERR_SOCKET_WOULD_BLOCK) WaitForSingleObject(ready, 10);
    } while ((status == PAL_ERR_SOCKET_IN_PROGRES || status == PAL_ERR_SOCKET_WOULD_BLOCK) && GetTickCount64() < deadline);
    CHECK(status == PAL_SUCCESS || status == PAL_ERR_SOCKET_ALREADY_CONNECTED);
    OK(pal_plat_initTLSConf(&configuration, PAL_TLS_MODE, PAL_TLS_IS_CLIENT));
    _Static_assert(PAL_TLS_CIPHER_SUITE == PAL_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_SUITE,
        "TLS fixture must match the Windows cloud cipher default");
    OK(pal_plat_setCipherSuites(configuration, PAL_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256));
    OK(pal_plat_setAuthenticationMode(configuration, PAL_TLS_VERIFY_REQUIRED));
    if (trust_certificate) {
        der_length = i2d_X509(certificate, &der); CHECK(der_length > 0);
        ca.buffer = der; ca.size = (uint32_t)der_length;
        OK(pal_plat_setCAChain(configuration, &ca, NULL));
    }
    if (client_auth) {
        palX509_t own;
        palPrivateKey_t private_key;
        der_length = i2d_X509(client_certificate, &client_der); CHECK(der_length > 0);
        own.buffer = client_der; own.size = (uint32_t)der_length;
        der_length = i2d_PrivateKey(client_key, &private_der); CHECK(der_length > 0);
        private_key.buffer = private_der; private_key.size = (uint32_t)der_length;
        OK(pal_plat_setOwnCertChain(configuration, &own));
        OK(pal_plat_setOwnPrivateKey(configuration, &private_key));
    }
    OK(pal_plat_initTLS(configuration, &tls));
    OK(pal_plat_sslSetup(tls, configuration));
    transport.socket = client; transport.transportationMode = PAL_TLS_MODE;
    OK(pal_plat_tlsSetSocket(configuration, &transport));
    status = pal_plat_handShake(tls, &server_time);
    CHECK(retry(status)); /* The server is deliberately paused at this point. */
    CHECK(SetEvent(fixture.go));
    deadline = GetTickCount64() + 5000;
    while (retry(status) && GetTickCount64() < deadline) {
        WaitForSingleObject(ready, 10);
        status = pal_plat_handShake(tls, &server_time);
    }
    if (trust_certificate) {
        OK(status);
        OK(pal_plat_sslGetVerifyResultExtended(tls, &verification)); CHECK(verification == 0);
        transferred = 0;
        OK(pal_plat_sslWrite(tls, payload, sizeof(payload), &transferred)); CHECK(transferred == sizeof(payload));
        deadline = GetTickCount64() + 5000;
        do {
            status = pal_plat_sslRead(tls, buffer, sizeof(buffer), &transferred);
            if (retry(status)) WaitForSingleObject(ready, 10);
        } while (retry(status) && GetTickCount64() < deadline);
        OK(status); CHECK(transferred == sizeof(payload) && memcmp(buffer, payload, sizeof(payload)) == 0);
    } else CHECK(status != PAL_SUCCESS && !retry(status));
    CHECK(WaitForSingleObject(worker, 5000) == WAIT_OBJECT_0);
    OK(pal_plat_freeTLS(&tls)); OK(pal_plat_tlsConfigurationFree(&configuration));
    /* Freeing TLS must not take ownership of the application PAL socket. */
    { bool nonblocking; OK(pal_isNonBlocking(client, &nonblocking)); CHECK(nonblocking); }
    OK(pal_close(&client));
    CloseHandle(worker); CloseHandle(ready); CloseHandle(fixture.go); closesocket(fixture.listener);
    OPENSSL_free(der); X509_free(certificate); EVP_PKEY_free(key); SSL_CTX_free(fixture.context);
    OPENSSL_free(client_der); OPENSSL_free(private_der); X509_free(client_certificate); EVP_PKEY_free(client_key);
    puts(client_auth ? "PASS shared OpenSSL: mutual certificate authentication over Windows PAL" :
        trust_certificate ? "PASS shared OpenSSL: verified TLS handshake and encrypted echo over Windows PAL" :
        "PASS shared OpenSSL: untrusted certificate rejected");
}

int main(void)
{
    puts(OpenSSL_version(OPENSSL_VERSION));
    OK(pal_plat_socketsInit(NULL)); OK(pal_plat_initTLSLibrary());
    test_tls(true, false); test_tls(false, false); test_tls(true, true);
    OK(pal_plat_cleanupTLS()); OK(pal_plat_socketsTerminate(NULL));
    return 0;
}
