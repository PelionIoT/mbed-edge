#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <time.h>
#include "ssl_platform.h"

/* Test certificate in PEM format (self-signed test certificate) */
static const char test_cert_pem[] = 
"-----BEGIN CERTIFICATE-----\n"
"MIIDozCCAougAwIBAgIUd4dPkxFEboYjdyHhp64Vd79QaC4wDQYJKoZIhvcNAQEL\n"
"BQAwYTELMAkGA1UEBhMCVVMxEjAQBgNVBAgMCVRlc3RTdGF0ZTERMA8GA1UEBwwI\n"
"VGVzdENpdHkxEDAOBgNVBAoMB1Rlc3RPcmcxGTAXBgNVBAMMEHRlc3QuZXhhbXBs\n"
"ZS5jb20wHhcNMjUwNjE3MjIzNzU0WhcNMjYwNjE3MjIzNzU0WjBhMQswCQYDVQQG\n"
"EwJVUzESMBAGA1UECAwJVGVzdFN0YXRlMREwDwYDVQQHDAhUZXN0Q2l0eTEQMA4G\n"
"A1UECgwHVGVzdE9yZzEZMBcGA1UEAwwQdGVzdC5leGFtcGxlLmNvbTCCASIwDQYJ\n"
"KoZIhvcNAQEBBQADggEPADCCAQoCggEBANnMzPzUs6SiMtmuFWvqsfJet8zETDS0\n"
"PkHD9a+jc7XHq3IfqOJUs+62rEFjWigLhCi+jLE98bucEjWIJXUiqxUCT9louLl/\n"
"cRck/Ayb3Gv+y/CaXmh2zA+psrq8/4uQ5x8OyRcBPlS3eMKWoibBqCIr1mSdI9sM\n"
"PZM70Mpt4WxiDWDXywXjNUIep5dhK0VPmiYKvq6Ky3ZQ29npKtMzbgR4d5Ji3Tf7\n"
"srA/rOeMyY2UeybnQCcW7PDR7ib+uMRCBPEvFYKdvPXqX/uRJ5L/Px6YtTnE10yg\n"
"EDjkvaLdVq5c1DvGVSc5lMjt6vvVAx21elFuuhE1XxQKj7TaVKyZnP0CAwEAAaNT\n"
"MFEwHQYDVR0OBBYEFJF8WCWV/7o6U6n1q1LQ4Se67Y1TMB8GA1UdIwQYMBaAFJF8\n"
"WCWV/7o6U6n1q1LQ4Se67Y1TMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQEL\n"
"BQADggEBAG5K9htsvgPAq95IwOZbqZ13iNt890E9ySZGOFhPP0Q/SE3NpR6EZeLS\n"
"Xn+aSZDYdT8ImYdYc1r102JUhUH17aRkjaMxF1k8D/VSnypjG9kRdNNBR/yBPwI2\n"
"NDMke9r+F3GTclfk4wKLWFDuMvjHfGchb/MWVB1uVcIXaU/rmMw/J/t5KAugJcD2\n"
"ssfEHeDcxozkfdoKE668VAL/icP5jGbOQjqC9HNsE9a9hNiqmuvyR93O4UOv4vG8\n"
"xdGEnyZzReVJ7kizgqmAgNYKVZNmw0q/RR0vM4RfUAJuhnejhhx43QPfzFRw23iF\n"
"/Acc+Yhuy2kfgwAcWu0/QkjPagRQZOA=\n"
"-----END CERTIFICATE-----\n";

/* Helper function to print hex data */
static void print_hex(const char *label, const unsigned char *data, size_t len) {
    printf("%s (%zu bytes): ", label, len);
    for (size_t i = 0; i < len && i < 32; i++) {  // Limit output for readability
        printf("%02x", data[i]);
    }
    if (len > 32) {
        printf("...");
    }
    printf("\n");
}

/* Test ssl_platform_x509_crt_parse and basic certificate loading */
static int test_certificate_parsing(ssl_platform_x509_crt_t *cert) {
    printf("\n=== Testing Certificate Parsing ===\n");
    
    ssl_platform_x509_crt_init(cert);
    
    int ret = ssl_platform_x509_crt_parse(cert, (const unsigned char*)test_cert_pem, strlen(test_cert_pem) + 1);
    if (ret != SSL_PLATFORM_SUCCESS) {
        printf("FAIL: Failed to parse certificate: %d\n", ret);
        return -1;
    }
    
    printf("PASS: Certificate parsed successfully\n");
    return 0;
}

/* Test ssl_platform_x509_get_subject_name */
static int test_get_subject_name(ssl_platform_x509_crt_t *cert) {
    printf("\n=== Testing Get Subject Name ===\n");
    
    char subject_buf[512];
    int ret = ssl_platform_x509_get_subject_name(cert, subject_buf, sizeof(subject_buf));
    if (ret != SSL_PLATFORM_SUCCESS) {
        printf("FAIL: Failed to get subject name: %d\n", ret);
        return -1;
    }
    
    printf("Subject: %s\n", subject_buf);
    printf("PASS: Subject name retrieved successfully\n");
    return 0;
}

/* Test ssl_platform_x509_get_issuer_raw */
static int test_get_issuer_raw(ssl_platform_x509_crt_t *cert) {
    printf("\n=== Testing Get Issuer Raw ===\n");
    
    unsigned char *issuer_buf = NULL;
    size_t issuer_len = 0;
    
    int ret = ssl_platform_x509_get_issuer_raw(cert, &issuer_buf, &issuer_len);
    if (ret != SSL_PLATFORM_SUCCESS) {
        printf("FAIL: Failed to get issuer raw: %d\n", ret);
        return -1;
    }
    
    if (issuer_buf == NULL || issuer_len == 0) {
        printf("FAIL: Invalid issuer data returned\n");
        return -1;
    }
    
    print_hex("Issuer DER", issuer_buf, issuer_len);
    
    // Free the allocated buffer - use standard free since ssl-platform handles the backend
    free(issuer_buf);
    
    printf("PASS: Issuer raw data retrieved successfully\n");
    return 0;
}

/* Test ssl_platform_x509_get_subject_raw */
static int test_get_subject_raw(ssl_platform_x509_crt_t *cert) {
    printf("\n=== Testing Get Subject Raw ===\n");
    
    unsigned char *subject_buf = NULL;
    size_t subject_len = 0;
    
    int ret = ssl_platform_x509_get_subject_raw(cert, &subject_buf, &subject_len);
    if (ret != SSL_PLATFORM_SUCCESS) {
        printf("FAIL: Failed to get subject raw: %d\n", ret);
        return -1;
    }
    
    if (subject_buf == NULL || subject_len == 0) {
        printf("FAIL: Invalid subject data returned\n");
        return -1;
    }
    
    print_hex("Subject DER", subject_buf, subject_len);
    
    // Free the allocated buffer - use standard free since ssl-platform handles the backend
    free(subject_buf);
    
    printf("PASS: Subject raw data retrieved successfully\n");
    return 0;
}

/* Test ssl_platform_x509_get_validity */
static int test_get_validity(ssl_platform_x509_crt_t *cert) {
    printf("\n=== Testing Get Validity ===\n");
    
    struct tm not_before, not_after;
    
    int ret = ssl_platform_x509_get_validity(cert, &not_before, &not_after);
    if (ret != SSL_PLATFORM_SUCCESS) {
        printf("FAIL: Failed to get validity: %d\n", ret);
        return -1;
    }
    
    char before_str[64], after_str[64];
    strftime(before_str, sizeof(before_str), "%Y-%m-%d %H:%M:%S", &not_before);
    strftime(after_str, sizeof(after_str), "%Y-%m-%d %H:%M:%S", &not_after);
    
    printf("Valid from: %s\n", before_str);
    printf("Valid to:   %s\n", after_str);
    
    printf("PASS: Validity dates retrieved successfully\n");
    return 0;
}

/* Test ssl_platform_x509_get_signature */
static int test_get_signature(ssl_platform_x509_crt_t *cert) {
    printf("\n=== Testing Get Signature ===\n");
    
    unsigned char *sig_buf = NULL;
    size_t sig_len = 0;
    
    int ret = ssl_platform_x509_get_signature(cert, &sig_buf, &sig_len);
    if (ret != SSL_PLATFORM_SUCCESS) {
        printf("FAIL: Failed to get signature: %d\n", ret);
        return -1;
    }
    
    if (sig_buf == NULL || sig_len == 0) {
        printf("FAIL: Invalid signature data returned\n");
        return -1;
    }
    
    print_hex("Signature", sig_buf, sig_len);
    
    // Free the allocated buffer
    free(sig_buf);
    
    printf("PASS: Signature retrieved successfully\n");
    return 0;
}

/* Test ssl_platform_x509_get_tbs */
static int test_get_tbs(ssl_platform_x509_crt_t *cert) {
    printf("\n=== Testing Get TBS ===\n");
    
    unsigned char *tbs_buf = NULL;
    size_t tbs_len = 0;
    
    int ret = ssl_platform_x509_get_tbs(cert, &tbs_buf, &tbs_len);
    if (ret != SSL_PLATFORM_SUCCESS) {
        printf("FAIL: Failed to get TBS: %d\n", ret);
        return -1;
    }
    
    if (tbs_buf == NULL || tbs_len == 0) {
        printf("FAIL: Invalid TBS data returned\n");
        return -1;
    }
    
    print_hex("TBS Certificate", tbs_buf, tbs_len);
    
    // Free the allocated buffer - use standard free since ssl-platform handles the backend
    free(tbs_buf);
    
    printf("PASS: TBS certificate retrieved successfully\n");
    return 0;
}

/* Test ssl_platform_x509_get_pubkey */
static int test_get_pubkey(ssl_platform_x509_crt_t *cert) {
    printf("\n=== Testing Get Public Key ===\n");
    
    ssl_platform_pk_context_t pk;
    ssl_platform_pk_init(&pk);
    
    int ret = ssl_platform_x509_get_pubkey(cert, &pk);
    if (ret != SSL_PLATFORM_SUCCESS) {
        printf("FAIL: Failed to get public key: %d\n", ret);
        ssl_platform_pk_free(&pk);
        return -1;
    }
    
    // Note: We can't directly access internal structure members in ssl-platform
    // The ssl_platform_pk_context_t is an opaque type
    // If extraction succeeded, assume the key is valid
    printf("PASS: Public key extracted successfully\n");
    
    ssl_platform_pk_free(&pk);
    return 0;
}

/* Test ssl_platform_x509_crt_check_extended_key_usage */
static int test_check_extended_key_usage(ssl_platform_x509_crt_t *cert) {
    printf("\n=== Testing Check Extended Key Usage ===\n");
    
    // Test with a common EKU OID (Server Authentication)
    const char *server_auth_oid = "1.3.6.1.5.5.7.3.1";
    
    int ret = ssl_platform_x509_crt_check_extended_key_usage(cert, 
                                                            (const unsigned char*)server_auth_oid, 
                                                            strlen(server_auth_oid));
    
    // Note: This might fail for our test certificate since it might not have EKU extension
    // That's okay - we're testing the function works, not that the certificate has specific extensions
    if (ret == SSL_PLATFORM_SUCCESS) {
        printf("Certificate has Server Authentication EKU\n");
        printf("PASS: Extended Key Usage check succeeded\n");
    } else if (ret == SSL_PLATFORM_ERROR_GENERIC) {
        printf("Certificate does not have Server Authentication EKU (or no EKU extension)\n");
        printf("PASS: Extended Key Usage check completed (expected result for test cert)\n");
    } else {
        printf("FAIL: Extended Key Usage check failed with error: %d\n", ret);
        return -1;
    }
    
    return 0;
}

/* Test ssl_platform_ctr_drbg_reseed */
static int test_ctr_drbg_reseed(void) {
    printf("\n=== Testing CTR-DRBG Reseed ===\n");
    
    ssl_platform_ctr_drbg_context_t ctx;
    ssl_platform_ctr_drbg_init(&ctx);
    
    // Test reseeding with additional entropy
    unsigned char additional_entropy[] = "test_entropy_data_12345";
    
    int ret = ssl_platform_ctr_drbg_reseed(&ctx, additional_entropy, sizeof(additional_entropy) - 1);
    if (ret != SSL_PLATFORM_SUCCESS) {
        printf("FAIL: CTR-DRBG reseed failed: %d\n", ret);
        ssl_platform_ctr_drbg_free(&ctx);
        return -1;
    }
    
    // Test reseeding without additional entropy
    ret = ssl_platform_ctr_drbg_reseed(&ctx, NULL, 0);
    if (ret != SSL_PLATFORM_SUCCESS) {
        printf("FAIL: CTR-DRBG reseed without additional entropy failed: %d\n", ret);
        ssl_platform_ctr_drbg_free(&ctx);
        return -1;
    }
    
    printf("PASS: CTR-DRBG reseed operations completed successfully\n");
    
    ssl_platform_ctr_drbg_free(&ctx);
    return 0;
}

/* Test parameter validation for all functions */
static int test_parameter_validation(void) {
    printf("\n=== Testing Parameter Validation ===\n");
    
    int failures = 0;
    
    // Test NULL parameters for various functions
    unsigned char *buf = NULL;
    size_t len = 0;
    char str_buf[64];
    struct tm tm_buf;
    ssl_platform_pk_context_t pk;
    
    // Test ssl_platform_x509_get_tbs with NULL parameters
    if (ssl_platform_x509_get_tbs(NULL, &buf, &len) != SSL_PLATFORM_ERROR_INVALID_PARAMETER) {
        printf("FAIL: x509_get_tbs should reject NULL certificate\n");
        failures++;
    }
    
    // Test ssl_platform_x509_get_subject_name with NULL parameters
    if (ssl_platform_x509_get_subject_name(NULL, str_buf, sizeof(str_buf)) != SSL_PLATFORM_ERROR_INVALID_PARAMETER) {
        printf("FAIL: x509_get_subject_name should reject NULL certificate\n");
        failures++;
    }
    
    // Test ssl_platform_x509_get_validity with NULL parameters
    if (ssl_platform_x509_get_validity(NULL, &tm_buf, &tm_buf) != SSL_PLATFORM_ERROR_INVALID_PARAMETER) {
        printf("FAIL: x509_get_validity should reject NULL certificate\n");
        failures++;
    }
    
    // Test ssl_platform_x509_get_pubkey with NULL parameters
    if (ssl_platform_x509_get_pubkey(NULL, &pk) != SSL_PLATFORM_ERROR_INVALID_PARAMETER) {
        printf("FAIL: x509_get_pubkey should reject NULL certificate\n");
        failures++;
    }
    
    // Test ssl_platform_ctr_drbg_reseed with NULL context
    if (ssl_platform_ctr_drbg_reseed(NULL, NULL, 0) != SSL_PLATFORM_ERROR_INVALID_PARAMETER) {
        printf("FAIL: ctr_drbg_reseed should reject NULL context\n");
        failures++;
    }
    
    if (failures == 0) {
        printf("PASS: All parameter validation tests passed\n");
        return 0;
    } else {
        printf("FAIL: %d parameter validation tests failed\n", failures);
        return -1;
    }
}

int main(void) {
    printf("=== SSL Platform X.509 and CTR-DRBG Test Suite ===\n");
    
    ssl_platform_x509_crt_t cert;
    int tests_passed = 0;
    int tests_failed = 0;
    
    // Test parameter validation first
    if (test_parameter_validation() == 0) {
        tests_passed++;
    } else {
        tests_failed++;
    }
    
    // Parse the test certificate first
    if (test_certificate_parsing(&cert) != 0) {
        printf("CRITICAL: Cannot parse test certificate - aborting remaining tests\n");
        return 1;
    }
    tests_passed++;
    
    // Run all certificate-related tests
    if (test_get_subject_name(&cert) == 0) {
        tests_passed++;
    } else {
        tests_failed++;
    }
    
    if (test_get_issuer_raw(&cert) == 0) {
        tests_passed++;
    } else {
        tests_failed++;
    }
    
    if (test_get_subject_raw(&cert) == 0) {
        tests_passed++;
    } else {
        tests_failed++;
    }
    
    if (test_get_validity(&cert) == 0) {
        tests_passed++;
    } else {
        tests_failed++;
    }
    
    if (test_get_signature(&cert) == 0) {
        tests_passed++;
    } else {
        tests_failed++;
    }
    
    if (test_get_tbs(&cert) == 0) {
        tests_passed++;
    } else {
        tests_failed++;
    }
    
    if (test_get_pubkey(&cert) == 0) {
        tests_passed++;
    } else {
        tests_failed++;
    }
    
    if (test_check_extended_key_usage(&cert) == 0) {
        tests_passed++;
    } else {
        tests_failed++;
    }
    
    // Test CTR-DRBG functions
    if (test_ctr_drbg_reseed() == 0) {
        tests_passed++;
    } else {
        tests_failed++;
    }
    
    // Clean up
    ssl_platform_x509_crt_free(&cert);
    
    printf("\n=== Test Results ===\n");
    printf("Tests passed: %d\n", tests_passed);
    printf("Tests failed: %d\n", tests_failed);
    
    if (tests_failed == 0) {
        printf("All tests PASSED!\n");
        return 0;
    } else {
        printf("Some tests FAILED!\n");
        return 1;
    }
} 