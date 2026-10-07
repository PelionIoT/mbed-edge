/* SPDX-License-Identifier: Apache-2.0 */
#include "developer_credentials.h"
#include <ctype.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

enum { IDENT = 256, NUMBER, STRING, END, BAD };
enum { BLOB_LIMIT = 16384, TEXT_LIMIT = 4096, FIELD_COUNT = 12 };
typedef struct { int kind; unsigned char text[BLOB_LIMIT]; size_t length; } token;
typedef struct { const unsigned char *p, *end; int failed; } lexer;
typedef struct { const char *cname, *name; int type; unsigned char *data; size_t length; uint32_t number; int found; } field;
typedef struct { unsigned char *data; size_t length; int failed; } buffer;

static int digit(unsigned char ch)
{
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}
static void next(lexer *l, token *t)
{
    const unsigned char *start;
    memset(t, 0, sizeof(*t));
    for (;;) {
        while (l->p < l->end && isspace(*l->p)) ++l->p;
        if (l->p == l->end) { t->kind = END; return; }
        if (l->end - l->p >= 2 && l->p[0] == '/' && l->p[1] == '/') {
            while (l->p < l->end && *l->p != '\n') ++l->p;
        } else if (l->end - l->p >= 2 && l->p[0] == '/' && l->p[1] == '*') {
            l->p += 2;
            while (l->end - l->p >= 2 && !(l->p[0] == '*' && l->p[1] == '/')) ++l->p;
            if (l->end - l->p < 2) { t->kind = BAD; return; }
            l->p += 2;
        } else if (*l->p == '#') {
            /* Portal files use only an include guard and standard includes.
             * Conditional definitions and macro expansion are unsupported. */
            ++l->p;
            while (l->p < l->end && (*l->p == ' ' || *l->p == '\t')) ++l->p;
            start = l->p;
            while (l->p < l->end && isalpha(*l->p)) ++l->p;
            if (!((l->p-start == 6 && !memcmp(start,"ifndef",6)) ||
                  (l->p-start == 6 && !memcmp(start,"define",6)) ||
                  (l->p-start == 7 && !memcmp(start,"include",7)) ||
                  (l->p-start == 5 && !memcmp(start,"endif",5)))) { t->kind = BAD; return; }
            while (l->p < l->end && *l->p != '\n') ++l->p;
        } else break;
    }
    start = l->p;
    if (isalpha(*l->p) || *l->p == '_') {
        t->kind = IDENT;
        while (l->p < l->end && (isalnum(*l->p) || *l->p == '_')) ++l->p;
    } else if (isdigit(*l->p)) {
        t->kind = NUMBER;
        while (l->p < l->end && isalnum(*l->p)) ++l->p;
    } else if (*l->p == '"') {
        t->kind = STRING; ++l->p;
        while (l->p < l->end && *l->p != '"') {
            unsigned int ch = *l->p++;
            if (ch == '\\') {
                int d;
                if (l->p == l->end) { t->kind = BAD; return; }
                ch = *l->p++;
                switch (ch) {
                case 'a': ch = 7; break; case 'b': ch = 8; break;
                case 't': ch = 9; break; case 'n': ch = 10; break;
                case 'v': ch = 11; break; case 'f': ch = 12; break;
                case 'r': ch = 13; break;
                case '\\': case '"': case '\'': case '?': break;
                case 'x':
                    ch = 0;
                    if (l->p == l->end || digit(*l->p) < 0) { t->kind = BAD; return; }
                    while (l->p < l->end && (d = digit(*l->p)) >= 0) {
                        ch = ch * 16 + (unsigned)d; ++l->p;
                        if (ch > 255) { t->kind = BAD; return; }
                    }
                    break;
                default:
                    if (ch >= '0' && ch <= '7') {
                        int count = 1; ch -= '0';
                        while (count++ < 3 && l->p < l->end && *l->p >= '0' && *l->p <= '7') ch = ch * 8 + *l->p++ - '0';
                        if (ch > 255) { t->kind = BAD; return; }
                    } else { t->kind = BAD; return; }
                }
            }
            if (!ch || ch == '\n' || ch == '\r' || t->length >= TEXT_LIMIT) { t->kind = BAD; return; }
            t->text[t->length++] = (unsigned char)ch;
        }
        if (l->p == l->end) { t->kind = BAD; return; }
        ++l->p; return;
    } else { t->kind = *l->p++; return; }
    t->length = (size_t)(l->p - start);
    if (t->length >= sizeof(t->text)) { t->kind = BAD; return; }
    memcpy(t->text, start, t->length);
}
static int number(const token *t, uint32_t *result)
{
    size_t i = 0; uint64_t value = 0; unsigned base = 10; int d, any = 0;
    if (t->kind != NUMBER) return 0;
    if (t->length > 2 && t->text[0] == '0' && (t->text[1] == 'x' || t->text[1] == 'X')) { base = 16; i = 2; }
    else if (t->length > 1 && t->text[0] == '0') base = 8;
    while (i < t->length && (d = digit(t->text[i])) >= 0 && (unsigned)d < base) {
        value = value * base + (unsigned)d; ++i; any = 1;
        if (value > UINT32_MAX) return 0;
    }
    while (i < t->length && (t->text[i] == 'u' || t->text[i] == 'U' || t->text[i] == 'l' || t->text[i] == 'L')) ++i;
    if (!any || i != t->length) return 0;
    *result = (uint32_t)value; return 1;
}
static int utf8(const unsigned char *p, size_t size)
{
    size_t i = 0;
    while (i < size) {
        uint32_t ch = p[i++], minimum; unsigned more;
        if (ch < 128) { if (!ch || ch < 32 || ch == 127) return 0; continue; }
        if (ch >= 0xc2 && ch <= 0xdf) { more = 1; minimum = 0x80; ch &= 31; }
        else if (ch >= 0xe0 && ch <= 0xef) { more = 2; minimum = 0x800; ch &= 15; }
        else if (ch >= 0xf0 && ch <= 0xf4) { more = 3; minimum = 0x10000; ch &= 7; }
        else return 0;
        while (more--) { if (i == size || (p[i] & 0xc0) != 0x80) return 0; ch = (ch << 6) | (p[i++] & 63); }
        if (ch < minimum || ch > 0x10ffff || (ch >= 0xd800 && ch <= 0xdfff)) return 0;
    }
    return 1;
}
static int parse(lexer *l, field *f)
{
    token t; uint32_t n;
    next(l,&t);
    if (t.kind == '[') {
        next(l,&t);
        if (t.kind == NUMBER) next(l,&t);
        if (t.kind != ']') return 0;
        next(l,&t);
    }
    if (t.kind != '=') return 0;
    next(l,&t);
    if (f->type == 2) {
        if (!number(&t,&f->number)) return 0;
        next(l,&t);
    } else {
        f->data = (unsigned char *)malloc(BLOB_LIMIT);
        if (!f->data) return 0;
        if (f->type == 0) {
            if (t.kind != '{') return 0;
            next(l,&t);
            while (t.kind != '}') {
                if (!number(&t,&n) || n > 255 || f->length >= BLOB_LIMIT) return 0;
                f->data[f->length++] = (unsigned char)n;
                next(l,&t);
                if (t.kind == ',') next(l,&t);
                else if (t.kind != '}') return 0;
            }
            next(l,&t);
        } else {
            if (t.kind != STRING) return 0;
            while (t.kind == STRING) {
                if (f->length + t.length > TEXT_LIMIT) return 0;
                memcpy(f->data + f->length,t.text,t.length); f->length += t.length;
                next(l,&t);
            }
            if (!utf8(f->data,f->length)) return 0;
        }
        if (!f->length) return 0;
    }
    return t.kind == ';';
}
static void bytes(buffer *b, const void *p, size_t size)
{
    if (b->failed || size > EDGE_CREDENTIAL_FILE_LIMIT - b->length) { b->failed = 1; return; }
    memcpy(b->data + b->length,p,size); b->length += size;
}
static void head(buffer *b, unsigned type, uint32_t value)
{
    unsigned char p[5]; size_t size;
    if (value < 24) { p[0] = (unsigned char)(type * 32 + value); size = 1; }
    else if (value <= 255) { p[0] = (unsigned char)(type * 32 + 24); p[1] = (unsigned char)value; size = 2; }
    else if (value <= 65535) { p[0] = (unsigned char)(type * 32 + 25); p[1] = (unsigned char)(value >> 8); p[2] = (unsigned char)value; size = 3; }
    else { p[0] = (unsigned char)(type * 32 + 26); p[1] = (unsigned char)(value >> 24); p[2] = (unsigned char)(value >> 16); p[3] = (unsigned char)(value >> 8); p[4] = (unsigned char)value; size = 5; }
    bytes(b,p,size);
}
static void text(buffer *b, const char *s) { size_t n = strlen(s); head(b,3,(uint32_t)n); bytes(b,s,n); }
static void item(buffer *b, const field *f)
{
    head(b,5,(f->type == 0) ? (strstr(f->name,"PrivateKey") ? 4u : 3u) : 2u);
    text(b,"Name"); text(b,f->name); text(b,"Data");
    if (f->type == 2) head(b,0,f->number);
    else { head(b,f->type == 0 ? 2u : 3u,(uint32_t)f->length); bytes(b,f->data,f->length); }
    if (f->type == 0) { text(b,"Format"); text(b,"der"); if (strstr(f->name,"PrivateKey")) { text(b,"Type"); text(b,"ECCPrivate"); } }
}
int edge_convert_developer(const unsigned char *source, size_t length, unsigned char **output, size_t *output_length, const char **error)
{
    field f[FIELD_COUNT] = {
        {"MBED_CLOUD_DEV_BOOTSTRAP_DEVICE_CERTIFICATE","mbed.BootstrapDeviceCert",0,0,0,0,0},
        {"MBED_CLOUD_DEV_BOOTSTRAP_SERVER_ROOT_CA_CERTIFICATE","mbed.BootstrapServerCACert",0,0,0,0,0},
        {"MBED_CLOUD_DEV_BOOTSTRAP_DEVICE_PRIVATE_KEY","mbed.BootstrapDevicePrivateKey",0,0,0,0,0},
        {"MBED_CLOUD_DEV_BOOTSTRAP_ENDPOINT_NAME","mbed.EndpointName",1,0,0,0,0},
        {"MBED_CLOUD_DEV_BOOTSTRAP_SERVER_URI","mbed.BootstrapServerURI",1,0,0,0,0},
        {"MBED_CLOUD_DEV_ACCOUNT_ID","mbed.AccountID",1,0,0,0,0},
        {"MBED_CLOUD_DEV_MANUFACTURER","mbed.Manufacturer",1,0,0,0,0},
        {"MBED_CLOUD_DEV_MODEL_NUMBER","mbed.ModelNumber",1,0,0,0,0},
        {"MBED_CLOUD_DEV_SERIAL_NUMBER","mbed.SerialNumber",1,0,0,0,0},
        {"MBED_CLOUD_DEV_DEVICE_TYPE","mbed.DeviceType",1,0,0,0,0},
        {"MBED_CLOUD_DEV_HARDWARE_VERSION","mbed.HardwareVersion",1,0,0,0,0},
        {"MBED_CLOUD_DEV_MEMORY_TOTAL_KB","mbed.MemoryTotalKB",2,0,0,0,0}
    };
    lexer l; token t; buffer b = {0,0,0}; int i, ok = 0, declaration = 0;
    X509 *cert = NULL, *ca = NULL; EVP_PKEY *key = NULL; EVP_PKEY_CTX *keycheck = NULL; const unsigned char *p;
    *output = NULL; *output_length = 0; *error = "Malformed or unsupported developer credential declarations.";
    if (!source || !length || length > EDGE_CREDENTIAL_FILE_LIMIT || memchr(source,0,length)) goto cleanup;
    l.p = source; l.end = source + length; l.failed = 0;
    if (length >= 3 && !memcmp(source,"\xef\xbb\xbf",3)) l.p += 3;
    for (;;) {
        next(&l,&t);
        if (t.kind == END) break;
        if (t.kind == BAD) goto cleanup;
        if (t.kind == ';') { declaration = 0; continue; }
        if (t.kind == '=') { declaration = 0; continue; }
        if (t.kind == IDENT && !strcmp((const char *)t.text,"const")) declaration = 1;
        if (t.kind != IDENT || !declaration) continue;
        for (i = 0; i < FIELD_COUNT; ++i) if (!strcmp((const char *)t.text,f[i].cname)) {
            if (f[i].found) { *error = "Duplicate developer credential declaration."; goto cleanup; }
            if (!parse(&l,&f[i])) goto cleanup;
            f[i].found = 1; declaration = 0; break;
        }
    }
    for (i = 0; i < FIELD_COUNT; ++i) if (!f[i].found) { *error = "A required developer credential declaration is missing."; goto cleanup; }
    *error = "Credentials must contain complete DER certificates and a matching EC private key.";
    p = f[0].data; cert = d2i_X509(NULL,&p,(long)f[0].length);
    if (!cert || p != f[0].data + f[0].length) goto cleanup;
    p = f[1].data; ca = d2i_X509(NULL,&p,(long)f[1].length);
    if (!ca || p != f[1].data + f[1].length) goto cleanup;
    p = f[2].data; key = d2i_AutoPrivateKey(NULL,&p,(long)f[2].length);
    if (!key || p != f[2].data + f[2].length || !EVP_PKEY_is_a(key,"EC") || X509_check_private_key(cert,key) != 1) goto cleanup;
    keycheck = EVP_PKEY_CTX_new_from_pkey(NULL,key,NULL);
    if (!keycheck || EVP_PKEY_pairwise_check(keycheck) != 1) goto cleanup;
    *error = "Could not allocate the provisioning bundle.";
    b.data = (unsigned char *)malloc(EDGE_CREDENTIAL_FILE_LIMIT);
    if (!b.data) goto cleanup;
    head(&b,5,4); text(&b,"SchemeVersion"); text(&b,"0.0.1");
    text(&b,"Certificates"); head(&b,4,2); item(&b,&f[0]); item(&b,&f[1]);
    text(&b,"Keys"); head(&b,4,1); item(&b,&f[2]);
    text(&b,"ConfigParams"); head(&b,4,10); head(&b,5,2);
    text(&b,"Name"); text(&b,"mbed.UseBootstrap"); text(&b,"Data"); head(&b,0,1);
    for (i = 3; i < FIELD_COUNT; ++i) item(&b,&f[i]);
    if (b.failed) goto cleanup;
    *output = b.data; *output_length = b.length; b.data = NULL; *error = NULL; ok = 1;
cleanup:
    for (i = 0; i < FIELD_COUNT; ++i) if (f[i].data) { OPENSSL_cleanse(f[i].data,BLOB_LIMIT); free(f[i].data); }
    if (b.data) { OPENSSL_cleanse(b.data,EDGE_CREDENTIAL_FILE_LIMIT); free(b.data); }
    OPENSSL_cleanse(&t,sizeof(t)); X509_free(cert); X509_free(ca); EVP_PKEY_CTX_free(keycheck); EVP_PKEY_free(key);
    return ok;
}
