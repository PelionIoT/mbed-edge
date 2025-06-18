#include "ssl_platform.h"
#include <stdio.h>
#include <string.h>

int test_asn1_write_functions() {
    unsigned char buffer[1024];
    unsigned char *p = buffer + sizeof(buffer);
    unsigned char *start = buffer;
    int ret;

    printf("Testing ASN.1 write functions...\n");

    // Test writing a simple integer
    ret = ssl_platform_asn1_write_int(&p, start, 42);
    if (ret < 0) {
        printf("Failed to write integer: %d\n", ret);
        return -1;
    }
    printf("Successfully wrote integer, %d bytes\n", ret);

    // Test writing a tag
    ret = ssl_platform_asn1_write_tag(&p, start, 0x02);
    if (ret < 0) {
        printf("Failed to write tag: %d\n", ret);
        return -1;
    }
    printf("Successfully wrote tag, %d bytes\n", ret);

    // Test writing length
    ret = ssl_platform_asn1_write_len(&p, start, 10);
    if (ret < 0) {
        printf("Failed to write length: %d\n", ret);
        return -1;
    }
    printf("Successfully wrote length, %d bytes\n", ret);

    return 0;
}

int test_asn1_oid_functions() {
    const char *short_name;
    ssl_platform_asn1_buf oid_buf;
    
    printf("Testing OID functions...\n");
    
    // Create a simple test OID buffer (this is just a basic test)
    unsigned char oid_data[] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01}; // RSA OID
    oid_buf.p = oid_data;
    oid_buf.len = sizeof(oid_data);
    
    int ret = ssl_platform_oid_get_attr_short_name(&oid_buf, &short_name);
    if (ret == SSL_PLATFORM_SUCCESS) {
        printf("Successfully got OID short name: %s\n", short_name ? short_name : "NULL");
    } else {
        printf("OID lookup failed: %d\n", ret);
    }
    
    return 0;
}

int main() {
    printf("SSL Platform ASN.1 Function Test\n");
    printf("=================================\n");

    if (test_asn1_write_functions() != 0) {
        printf("ASN.1 write function tests failed\n");
        return 1;
    }

    if (test_asn1_oid_functions() != 0) {
        printf("OID function tests failed\n");
        return 1;
    }

    printf("All tests passed!\n");
    return 0;
} 