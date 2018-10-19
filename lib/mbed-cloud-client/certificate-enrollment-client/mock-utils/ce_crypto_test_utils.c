// ----------------------------------------------------------------------------
// Copyright 2018 ARM Ltd.
//  
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//  
//     http://www.apache.org/licenses/LICENSE-2.0
//  
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// ----------------------------------------------------------------------------

#ifdef CERT_RENEWAL_TEST

#include "entropy.h"
#include "ctr_drbg.h"
#include "x509_csr.h"
#include "x509_crt.h"
#include "pk.h"
#include "ce_crypto_test_utils.h"
#include "pv_error_handling.h"

#define CERTIFICATE_X509_TEST_MAX_SIZE 1024

static const uint8_t key_1der[138] = { 0x30, 0x81, 0x87, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x04, 0x6d, 0x30, 0x6b, 0x02, 0x01, 0x01, 0x04, 0x20, 0xa2, 0x5f, 0x7b, 0x59, 0x5d, 0xac, 0x79, 0xae, 0x25, 0xc7, 0x3e, 0x87, 0xd2, 0x05, 0xc1, 0x1f, 0x57, 0x98, 0x32, 0x28, 0x00, 0x74, 0xe6, 0xc8, 0xa8, 0xe8, 0xfc, 0xa5, 0x73, 0x3e, 0x0c, 0x9f, 0xa1, 0x44, 0x03, 0x42, 0x00, 0x04, 0x7d, 0xc7, 0xc1, 0xce, 0x37, 0x97, 0xb7, 0x0b, 0x6e, 0x02, 0x20, 0x1e, 0x99, 0xa2, 0xc8, 0x40, 0xa6, 0xff, 0xec, 0x27, 0x57, 0x6e, 0x1c, 0xa5, 0xc1, 0x8c, 0xbf, 0xa2, 0x38, 0xdd, 0xd9, 0xd1, 0xe7, 0x34, 0x23, 0xf0, 0x48, 0x80, 0x5a, 0xb4, 0xee, 0xa9, 0xe8, 0xb7, 0x29, 0x64, 0x8d, 0xd6, 0x2c, 0x4c, 0x9a, 0xf9, 0x54, 0x18, 0x43, 0x08, 0x0e, 0xda, 0xf9, 0x4a, 0x20, 0xd5, 0x7c, 0x4b, };

// NOTE - not all the below defines are in use.

#define DFL_ISSUER_CRT          ""
#define DFL_REQUEST_FILE        ""
#define DFL_SUBJECT_KEY         ""
#define DFL_ISSUER_KEY          key_1der
#define DFL_ISSUER_KEY_SIZE     sizeof(key_1der)
#define DFL_OUTPUT_FILENAME     ""
#define DFL_SUBJECT_NAME        ""
#define DFL_ISSUER_NAME         "CN=CA,O=ARM,C=UK"
#define DFL_NOT_BEFORE          "20010101000000"
#define DFL_NOT_AFTER           "20301231235959"
#define DFL_SERIAL              "123454321"
#define DFL_SELFSIGN            0
#define DFL_IS_CA               0
#define DFL_MAX_PATHLEN         -1
#define DFL_KEY_USAGE           1
#define DFL_NS_CERT_TYPE        0
#define DFL_VERSION             2
#define DFL_AUTH_IDENT          1
#define DFL_SUBJ_IDENT          1
#define DFL_CONSTRAINTS         1
#define DFL_DIGEST              MBEDTLS_MD_SHA256

struct options {
    const char *issuer_crt;     /* filename of the issuer certificate   */
    const char *request_file;   /* filename of the certificate request  */
    const char *subject_key;    /* filename of the subject key file     */
    const uint8_t *issuer_key;  /* the of the issuer key bytes          */
    size_t issuer_key_size;     /* the of the issuer key bytes length   */
    const char *output_file;    /* where to store the constructed key file  */
    const char *subject_name;   /* subject name for certificate         */
    const char *issuer_name;    /* issuer name for certificate          */
    const char *not_before;     /* validity period not before           */
    const char *not_after;      /* validity period not after            */
    const char *serial;         /* serial number string                 */
    int selfsign;               /* selfsign the certificate             */
    int is_ca;                  /* is a CA certificate                  */
    int max_pathlen;            /* maximum CA path length               */
    int authority_identifier;   /* add authority identifier to CRT      */
    int subject_identifier;     /* add subject identifier to CRT        */
    int basic_constraints;      /* add basic constraints ext to CRT     */
    int version;                /* CRT version                          */
    mbedtls_md_type_t md;       /* Hash used for signing                */
    unsigned char key_usage;    /* key usage flags                      */
    unsigned char ns_cert_type; /* NS cert type                         */
} opt;


static bool _create_x509_crt_from_csr(mbedtls_x509_csr *csr, unsigned char *crt_der_out, size_t crt_der_max_size, size_t *crt_der_size_out)
{
    int ret = 0;
    char buf[1024];
    char subject_name[256];
    unsigned char temp_crt_buff[CERTIFICATE_X509_TEST_MAX_SIZE];
    mbedtls_pk_context loaded_issuer_key;
    mbedtls_x509write_cert crt;
    mbedtls_mpi serial;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "crt example app";

    /*
    * Set to sane values
    */
    mbedtls_x509write_crt_init(&crt);
    mbedtls_pk_init(&loaded_issuer_key);
    mbedtls_mpi_init(&serial);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    memset(buf, 0, 1024);

    // NOTE - not all the below fields are in use.
    // - The relevant attributes are taken from the CSR.
    // - The resulting certificate is not meant to be self-signed
    //   and does not carry any extension due to mbedtls incapability

    opt.issuer_crt = DFL_ISSUER_CRT;
    opt.request_file = DFL_REQUEST_FILE;
    opt.subject_key = DFL_SUBJECT_KEY;
    opt.issuer_key = DFL_ISSUER_KEY;
    opt.issuer_key_size = DFL_ISSUER_KEY_SIZE;
    opt.output_file = DFL_OUTPUT_FILENAME;
    opt.subject_name = DFL_SUBJECT_NAME;
    opt.issuer_name = DFL_ISSUER_NAME;
    opt.not_before = DFL_NOT_BEFORE;
    opt.not_after = DFL_NOT_AFTER;
    opt.serial = DFL_SERIAL;
    opt.selfsign = DFL_SELFSIGN;
    opt.is_ca = DFL_IS_CA;
    opt.max_pathlen = DFL_MAX_PATHLEN;
    opt.key_usage = DFL_KEY_USAGE;
    opt.ns_cert_type = DFL_NS_CERT_TYPE;
    opt.version = DFL_VERSION;
    opt.md = DFL_DIGEST;
    opt.subject_identifier = DFL_SUBJ_IDENT;
    opt.authority_identifier = DFL_AUTH_IDENT;
    opt.basic_constraints = DFL_CONSTRAINTS;

    mbedtls_entropy_init(&entropy);
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers));
    SA_PV_ERR_RECOVERABLE_RETURN_IF((ret != 0), false, "mbedtls_ctr_drbg_seed error");

    ret = mbedtls_mpi_read_string(&serial, 10, opt.serial);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((ret != 0), false, "mbedtls_mpi_read_string error");

    // Get subject name
    ret = mbedtls_x509_dn_gets(subject_name, sizeof(subject_name), &csr->subject);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((ret < 0), false, "mbedtls_x509_dn_gets error");

    ret = mbedtls_pk_parse_key(&loaded_issuer_key, opt.issuer_key, opt.issuer_key_size, NULL, 0);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((ret != 0), false, "mbedtls_pk_parse_key error");

    // Set the issuer public key
    mbedtls_x509write_crt_set_issuer_key(&crt, &loaded_issuer_key);
    // Set the subject key (taken from the CSR)
    mbedtls_x509write_crt_set_subject_key(&crt, &csr->pk);

    /*
    * 1.0. Check the names for validity
    */
    ret = mbedtls_x509write_crt_set_subject_name(&crt, subject_name);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((ret != 0), false, "mbedtls_x509write_crt_set_subject_name error");

    ret = mbedtls_x509write_crt_set_issuer_name(&crt, opt.issuer_name);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((ret != 0), false, "mbedtls_x509write_crt_set_issuer_name error");

    mbedtls_x509write_crt_set_version(&crt, opt.version);
    mbedtls_x509write_crt_set_md_alg(&crt, opt.md);

    ret = mbedtls_x509write_crt_set_serial(&crt, &serial);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((ret != 0), false, "mbedtls_x509write_crt_set_serial error");

    ret = mbedtls_x509write_crt_set_validity(&crt, opt.not_before, opt.not_after);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((ret != 0), false, "mbedtls_x509write_crt_set_validity error");

    /*
    * ATTENTION: skip extensions parsing - because there is no generic API for this matter in mbedtls
    *            it means that the resulting CERTIFICATE extension (if any) will be absence
    */

    /*
    * 1.2. Writing the request
    */
    ret = mbedtls_x509write_crt_der(&crt, temp_crt_buff, sizeof(temp_crt_buff), mbedtls_ctr_drbg_random, &ctr_drbg);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((ret <= 0), false, "mbedtls_x509write_crt_der error");

    *crt_der_size_out = (size_t)ret;

    // mbedtls is writing the data at the end of the buffer!
    // copy from temp buffer to the user beginning buffer (as it should...)
    memcpy(crt_der_out, (temp_crt_buff + sizeof(temp_crt_buff) - *crt_der_size_out), *crt_der_size_out);

    mbedtls_x509write_crt_free(&crt);
    mbedtls_pk_free(&loaded_issuer_key);
    mbedtls_mpi_free(&serial);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    return true;
}

bool create_x509_crt_from_csr(const unsigned char *csr_der, size_t csr_der_size, mbedtls_x509_crt *crt_out)
{
    int mbedtls_status;
    mbedtls_x509_csr x509_csr;

    unsigned char crt_buff_der[CERTIFICATE_X509_TEST_MAX_SIZE];
    size_t crt_der_len = 0;


    // parse CSR
    mbedtls_status = mbedtls_x509_csr_parse_der(&x509_csr, csr_der, csr_der_size);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((mbedtls_status != 0), false, "mbedtls_x509_csr_parse_der error");

    // create CRT from the CSR
    _create_x509_crt_from_csr(&x509_csr, crt_buff_der, sizeof(crt_buff_der), &crt_der_len);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((crt_der_len <= 0), false, "create_x509_certificate_from_csr error");


    // parse the resulting DER certificate into mbedtls object
    mbedtls_x509_crt_init(crt_out);
    mbedtls_status = mbedtls_x509_crt_parse_der(crt_out, crt_buff_der, crt_der_len);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((mbedtls_status != 0), false, "mbedtls_x509_crt_parse_der error");

    mbedtls_x509_csr_free(&x509_csr);
    return true;
}

#endif