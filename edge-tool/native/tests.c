/* SPDX-License-Identifier: Apache-2.0 */
/* All keys in these tests are freshly generated synthetic credentials. */
#include "developer_credentials.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

static int failures;
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"Failed at line %d: %s\n",__LINE__,#x); ++failures; } } while(0)
static char *fixture(EVP_PKEY *key, X509 *cert, const char *extra, int omit)
{
    unsigned char *der = NULL; char *source = (char *)calloc(1,EDGE_CREDENTIAL_FILE_LIMIT);
    size_t n = 0; int i, k, size;
    const char *blob_names[] = {"BOOTSTRAP_DEVICE_CERTIFICATE","BOOTSTRAP_SERVER_ROOT_CA_CERTIFICATE","BOOTSTRAP_DEVICE_PRIVATE_KEY"};
    const char *names[] = {"BOOTSTRAP_ENDPOINT_NAME","BOOTSTRAP_SERVER_URI","ACCOUNT_ID","MANUFACTURER","MODEL_NUMBER","SERIAL_NUMBER","DEVICE_TYPE","HARDWARE_VERSION"};
    if (!source) return NULL;
    n += (size_t)sprintf(source+n,"#ifndef TEST_CREDENTIALS_H\n#define TEST_CREDENTIALS_H\n#include <inttypes.h>\n");
    for (k = 0; k < 3; ++k) {
        size = k == 2 ? i2d_PrivateKey(key,&der) : i2d_X509(cert,&der);
        if (size <= 0) { free(source); return NULL; }
        n += (size_t)sprintf(source+n,"const uint8_t MBED_CLOUD_DEV_%s[] = {\n",blob_names[k]);
        for (i = 0; i < size; ++i) n += (size_t)sprintf(source+n,"0x%02x,%s",der[i],i%16 == 15 ? "\n" : " ");
        n += (size_t)sprintf(source+n,"};\nconst uint32_t MBED_CLOUD_DEV_%s_SIZE = sizeof(MBED_CLOUD_DEV_%s);\n",blob_names[k],blob_names[k]);
        OPENSSL_clear_free(der,(size_t)size); der = NULL;
    }
    for (k = 0; k < 8; ++k) if (k != omit) {
        if (k == 0 || k == 2) n += (size_t)sprintf(source+n,"const char MBED_CLOUD_DEV_%s[] = \"0123456789abcdef0123456789abcdef\";\n",names[k]);
        else if (k == 1) n += (size_t)sprintf(source+n,"const char MBED_CLOUD_DEV_%s[] = \"coaps://127.0.0.1:5684?aid=0123456789abcdef0123456789abcdef\";\n",names[k]);
        else n += (size_t)sprintf(source+n,"const char MBED_CLOUD_DEV_%s[] = \"test\" /* adjacent literals */ \"-\\x76\\141lue\";\n",names[k]);
    }
    n += (size_t)sprintf(source+n,"// const char MBED_CLOUD_DEV_ACCOUNT_ID[] = \"ignored\";\n"
        "const uint32_t MBED_CLOUD_DEV_MEMORY_TOTAL_KB = 1234UL;\n%s\n#endif\n",extra);
    (void)n; return source;
}
/* Independent CBOR reader: verify the entire result is well-formed, uses the
 * FCC scheme and contains binary DER rather than textual byte arrays. */
static unsigned read_head(const unsigned char **p, const unsigned char *end, unsigned *type)
{
    unsigned ch, n, value;
    if (*p == end) { ++failures; *type = 7; return 0; }
    ch = *(*p)++; *type = ch >> 5; value = ch & 31;
    if (value < 24) return value;
    if (value > 26) { ++failures; return 0; }
    n = 1u << (value - 24); value = 0;
    while (n--) { if (*p == end) { ++failures; return 0; } value = (value << 8) | *(*p)++; }
    return value;
}
static void inspect(const unsigned char **p, const unsigned char *end, unsigned depth, int *blobs, int *scheme, int *items)
{
    unsigned type, n, i;
    if (depth > 8) { ++failures; return; }
    n = read_head(p,end,&type);
    if (type == 0) return;
    if (type == 2 || type == 3) {
        if (n > (size_t)(end-*p)) { ++failures; return; }
        if (type == 2) { CHECK(n > 30); CHECK(**p == 0x30); ++*blobs; }
        if (type == 3 && n == 5 && !memcmp(*p,"0.0.1",5)) ++*scheme;
        if (type == 3 && n > 5 && !memcmp(*p,"mbed.",5)) ++*items;
        *p += n; return;
    }
    if (type != 4 && type != 5) { ++failures; return; }
    if (type == 5) n *= 2;
    if (n > 64) { ++failures; return; }
    for (i = 0; i < n; ++i) inspect(p,end,depth+1,blobs,scheme,items);
}
static void convert_case(char *source, int success)
{
    unsigned char *out = NULL; size_t size = 0; const char *error = NULL;
    int result = edge_convert_developer((const unsigned char *)source,strlen(source),&out,&size,&error);
    CHECK(result == success);
    if (success && result) {
        const unsigned char *p = out; int blobs = 0, scheme = 0, items = 0;
        inspect(&p,out+size,0,&blobs,&scheme,&items);
        CHECK(p == out+size); CHECK(blobs == 3); CHECK(scheme == 1); CHECK(items == 13); CHECK(!error);
    } else { CHECK(!out); CHECK(!size); CHECK(error); }
    if (out) { OPENSSL_cleanse(out,size); free(out); }
    OPENSSL_cleanse(source,strlen(source)); free(source);
}
int main(int argc, char **argv)
{
    EVP_PKEY *key = EVP_PKEY_Q_keygen(NULL,NULL,"EC","prime256v1");
    EVP_PKEY *wrong = EVP_PKEY_Q_keygen(NULL,NULL,"EC","prime256v1");
    X509 *cert = X509_new(); X509_NAME *name;
    CHECK(key && wrong && cert);
    if (!key || !wrong || !cert) return 1;
    CHECK(X509_set_version(cert,2)); CHECK(ASN1_INTEGER_set(X509_get_serialNumber(cert),1));
    CHECK(X509_gmtime_adj(X509_getm_notBefore(cert),0)); CHECK(X509_gmtime_adj(X509_getm_notAfter(cert),86400));
    CHECK(X509_set_pubkey(cert,key)); name = X509_get_subject_name(cert);
    CHECK(X509_NAME_add_entry_by_txt(name,"CN",MBSTRING_ASC,(const unsigned char *)"0123456789abcdef0123456789abcdef",-1,-1,0));
    {
        X509_EXTENSION *usage = X509V3_EXT_conf_nid(NULL,NULL,NID_ext_key_usage,"clientAuth");
        CHECK(usage); if (usage) { CHECK(X509_add_ext(cert,usage,-1)); X509_EXTENSION_free(usage); }
    }
    CHECK(X509_set_issuer_name(cert,name)); CHECK(X509_sign(cert,key,EVP_sha256()) > 0);
    if (argc == 3 && !strcmp(argv[1],"--write-fixture")) {
        char *s = fixture(key,cert,"",-1); FILE *file = fopen(argv[2],"wb");
        CHECK(s && file);
        if (s && file) { CHECK(fwrite(s,1,strlen(s),file) == strlen(s)); CHECK(!fclose(file)); }
        if (s) { OPENSSL_cleanse(s,strlen(s)); free(s); }
    } else CHECK(argc == 1);
    convert_case(fixture(key,cert,"",-1),1);
    convert_case(fixture(wrong,cert,"",-1),0);
    convert_case(fixture(key,cert,"",2),0);
    convert_case(fixture(key,cert,"const char MBED_CLOUD_DEV_ACCOUNT_ID[] = \"duplicate\";",-1),0);
    convert_case(fixture(key,cert,"#if 0\n#endif",-1),0);
    convert_case(fixture(key,cert,"/* unterminated",-1),0);
    { char *s = fixture(key,cert,"",-1); char *p = strstr(s,"0x30"); CHECK(p); if (p) memcpy(p,"0xff",4); convert_case(s,0); }
    { char *s = fixture(key,cert,"",-1); char *p = strstr(s,"1234UL"); CHECK(p); if (p) memcpy(p,"-1    ",6); convert_case(s,0); }
    X509_free(cert); EVP_PKEY_free(key); EVP_PKEY_free(wrong);
    if (!failures) puts("Native conversion: valid FCC CBOR, key match, declarations, missing/duplicate values, malformed DER and source checks passed.");
    return failures ? 1 : 0;
}
