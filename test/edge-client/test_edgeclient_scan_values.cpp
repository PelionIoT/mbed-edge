#include "CppUTest/TestHarness.h"

#include <arpa/inet.h>
extern "C" {
#include "edge-client/edge_client_format_values.h"
}
#include <string.h>

TEST_GROUP(edgeclient_scan_values) {
    void setup()
    {
    }

    void teardown()
    {
    }
};

TEST(edgeclient_scan_values, test_scan_integer_zero)
{
    uint8_t bytes[8] = {0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00};
    const char value_buffer[] = "0";
    const uint32_t value_length = sizeof(value_buffer);
    uint8_t *buf = NULL;
    size_t buf_len = text_format_to_value(LWM2M_INTEGER, (const uint8_t*)value_buffer, value_length, &buf);
    CHECK(buf_len > 0);
    MEMCMP_EQUAL(&bytes, buf, buf_len);
    free(buf);
}

TEST(edgeclient_scan_values, test_scan_integer_100)
{
    uint8_t bytes[8] = {0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x64};
    const char value_buffer[] = "100";
    const uint32_t value_length = sizeof(value_buffer);
    uint8_t *buf = NULL;
    size_t buf_len = text_format_to_value(LWM2M_INTEGER, (const uint8_t*)value_buffer, value_length, &buf);
    CHECK(buf_len > 0);
    MEMCMP_EQUAL(bytes, buf, buf_len);
    free(buf);
}

TEST(edgeclient_scan_values, test_scan_negative_integer)
{
    uint8_t bytes[8] = {0xFF, 0xFF, 0xFF, 0xFF,
                        0xFF, 0xFF, 0xFF, 0xFF};
    const char value_buffer[] = "-1";
    const uint32_t value_length = sizeof(value_buffer);
    uint8_t *buf = NULL;
    size_t buf_len = text_format_to_value(LWM2M_INTEGER, (const uint8_t*)value_buffer, value_length, &buf);
    CHECK(buf_len > 0);
    MEMCMP_EQUAL(bytes, buf, buf_len);
    free(buf);
}

TEST(edgeclient_scan_values, test_scan_float_zero)
{
    uint8_t bytes[8] = {0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00};
    const char value_buffer[] = "0.0";
    const uint32_t value_length = sizeof(value_buffer);
    uint8_t *buf = NULL;
    size_t buf_len = text_format_to_value(LWM2M_FLOAT, (const uint8_t*)value_buffer, value_length, &buf);
    CHECK(buf_len > 0);
    MEMCMP_EQUAL(bytes, buf, buf_len);
    free(buf);
}

TEST(edgeclient_scan_values, test_scan_float_101_and_bit_more)
{
    uint8_t bytes[8] = {0x40, 0x59, 0x47, 0xAE,
                        0x14, 0x7A, 0xE1, 0x48};
    const char value_buffer[] = "101.12";
    const uint32_t value_length = sizeof(value_buffer);
    uint8_t *buf = NULL;
    size_t buf_len = text_format_to_value(LWM2M_FLOAT, (const uint8_t*)value_buffer, value_length, &buf);
    CHECK(buf_len > 0);
    MEMCMP_EQUAL(bytes, buf, buf_len);
    free(buf);
}

TEST(edgeclient_scan_values, test_scan_negative_float)
{
    uint8_t bytes[8] = {0xC0, 0x09, 0xAE, 0x14,
                        0x7A, 0xE1, 0x47, 0xAE};
    const char value_buffer[] = "-3.21";
    const uint32_t value_length = sizeof(value_buffer);
    uint8_t *buf = NULL;
    size_t buf_len = text_format_to_value(LWM2M_FLOAT, (const uint8_t*)value_buffer, value_length, &buf);
    CHECK(buf_len > 0);
    MEMCMP_EQUAL(bytes, buf, buf_len);
    free(buf);
}

TEST(edgeclient_scan_values, test_scan_high_precision_float)
{
    uint8_t bytes[8] = {0x3F, 0x89, 0x48, 0xB0,
                        0xF8, 0xFA, 0xB5, 0xE6};
    const char value_buffer[] = "0.0123456789";
    const uint32_t value_length = sizeof(value_buffer);
    uint8_t *buf = NULL;
    size_t buf_len = text_format_to_value(LWM2M_FLOAT, (const uint8_t*)value_buffer, value_length, &buf);
    CHECK(buf_len > 0);
    MEMCMP_EQUAL(bytes, buf, buf_len);
    free(buf);
}

TEST(edgeclient_scan_values, test_scan_high_precision_double)
{
    uint8_t bytes[8] = {0x3F, 0x89, 0x48, 0xB0,
                        0xF9, 0x05, 0x91, 0xE1};
    const char value_buffer[] = "0.01234567890123456";
    const uint32_t value_length = sizeof(value_buffer);
    uint8_t *buf = NULL;
    size_t buf_len = text_format_to_value(LWM2M_FLOAT, (const uint8_t*)value_buffer, value_length, &buf);
    CHECK(buf_len > 0);
    MEMCMP_EQUAL(bytes, buf, buf_len);
    free(buf);
}

TEST(edgeclient_scan_values, test_scan_bool_true)
{
    uint8_t bytes[1] = {0x01};
    const char value_buffer[] = "1";
    const uint32_t value_length = sizeof(value_buffer);
    uint8_t *buf = NULL;
    size_t buf_len = text_format_to_value(LWM2M_BOOLEAN, (const uint8_t*)value_buffer, value_length, &buf);
    CHECK(buf_len > 0);
    MEMCMP_EQUAL(bytes, buf, buf_len);
    free(buf);
}

TEST(edgeclient_scan_values, test_scan_bool_false)
{
    uint8_t bytes[1] = {0x00};
    const char value_buffer[] = "0";
    const uint32_t value_length = sizeof(value_buffer);
    uint8_t *buf = NULL;
    size_t buf_len = text_format_to_value(LWM2M_BOOLEAN, (const uint8_t*)value_buffer, value_length, &buf);
    CHECK(buf_len > 0);
    MEMCMP_EQUAL(bytes, buf, buf_len);
    free(buf);
}

TEST(edgeclient_scan_values, scan_uint8_t_tiny)
{
    uint8_t bytes[8] = {0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x7F};
    const char value_buffer[] = "127";
    const uint32_t value_length = sizeof(value_buffer);
    uint8_t *buf = NULL;
    size_t buf_len = text_format_to_value(LWM2M_INTEGER, (const uint8_t*)value_buffer, value_length, &buf);
    CHECK(buf_len > 0);
    MEMCMP_EQUAL(bytes, buf, buf_len);
    free(buf);
}

TEST(edgeclient_scan_values, scan_uint8_t_negative_tiny)
{
    uint8_t bytes[8] = {0xFF, 0xFF, 0xFF, 0xFF,
                        0xFF, 0xFF, 0xFF, 0x81};
    const char value_buffer[] = "-127";
    const uint32_t value_length = sizeof(value_buffer);
    uint8_t *buf = NULL;
    size_t buf_len = text_format_to_value(LWM2M_INTEGER, (const uint8_t*)value_buffer, value_length, &buf);
    CHECK(buf_len > 0);
    MEMCMP_EQUAL(bytes, buf, buf_len);
    free(buf);
}

TEST(edgeclient_scan_values, scan_uint8_t_small)
{
    uint8_t bytes[8] = {0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x7F, 0xFF};
    const char value_buffer[] = "32767";
    const uint32_t value_length = sizeof(value_buffer);
    uint8_t *buf = NULL;
    size_t buf_len = text_format_to_value(LWM2M_INTEGER, (const uint8_t*)value_buffer, value_length, &buf);
    CHECK(buf_len > 0);
    MEMCMP_EQUAL(bytes, buf, buf_len);
    free(buf);
}

TEST(edgeclient_scan_values, scan_uint8_t_negative_small)
{
    uint8_t bytes[8] = {0xFF, 0xFF, 0xFF, 0xFF,
                        0xFF, 0xFF, 0x80, 0x01};
    const char value_buffer[] = "-32767";
    const uint32_t value_length = sizeof(value_buffer);
    uint8_t *buf = NULL;
    size_t buf_len = text_format_to_value(LWM2M_INTEGER, (const uint8_t*)value_buffer, value_length, &buf);
    CHECK(buf_len > 0);
    MEMCMP_EQUAL(bytes, buf, buf_len);
    free(buf);
}

TEST(edgeclient_scan_values, scan_uint8_t_large)
{
    uint8_t bytes[8] = {0x00, 0x00, 0x00, 0x00,
                        0x00, 0x07, 0xD3, 0x69};
    const char value_buffer[] = "512873";
    const uint32_t value_length = sizeof(value_buffer);
    uint8_t *buf = NULL;
    size_t buf_len = text_format_to_value(LWM2M_INTEGER, (const uint8_t*)value_buffer, value_length, &buf);
    CHECK(buf_len > 0);
    MEMCMP_EQUAL(bytes, buf, buf_len);
    free(buf);
}

TEST(edgeclient_scan_values, scan_uint8_t_huge)
{
    uint8_t bytes[8] = {0x07, 0x1E, 0x16, 0xA6,
                        0x9F, 0x19, 0xA8, 0xE7};
    const char value_buffer[] = "512872312456456423";
    const uint32_t value_length = sizeof(value_buffer);
    uint8_t *buf = NULL;
    size_t buf_len = text_format_to_value(LWM2M_INTEGER, (const uint8_t*)value_buffer, value_length, &buf);
    CHECK(buf_len > 0);
    MEMCMP_EQUAL(bytes, buf, buf_len);
    free(buf);
}

TEST(edgeclient_scan_values, scan_uint8_t_float)
{
    uint8_t bytes[8] = {0x40, 0x9E, 0xDD, 0x2F,
                        0x1A, 0x9F, 0xBE, 0x77};
    const char value_buffer[] = "1975.296";
    const uint32_t value_length = sizeof(value_buffer);
    uint8_t *buf = NULL;
    size_t buf_len = text_format_to_value(LWM2M_FLOAT, (const uint8_t*)value_buffer, value_length, &buf);
    CHECK(buf_len > 0);
    MEMCMP_EQUAL(bytes, buf, buf_len);
    free(buf);
}

TEST(edgeclient_scan_values, scan_uint8_t_negative_float)
{
    uint8_t bytes[8] = {0xC0, 0x9E, 0xDD, 0x2F,
                        0x1A, 0x9F, 0xBE, 0x77};
    const char value_buffer[] = "-1975.296";
    const uint32_t value_length = sizeof(value_buffer);
    uint8_t *buf = NULL;
    size_t buf_len = text_format_to_value(LWM2M_FLOAT, (const uint8_t*)value_buffer, value_length, &buf);
    CHECK(buf_len > 0);
    MEMCMP_EQUAL(bytes, buf, buf_len);
    free(buf);
}


TEST(edgeclient_scan_values, scan_uint8_t_double)
{
    uint8_t bytes[8] = {0x3C, 0x6C, 0x77, 0x8E,
                        0x53, 0x28, 0x03, 0x42};
    const char value_buffer[] = "0.0000000000000000123456";
    const uint32_t value_length = sizeof(value_buffer);
    uint8_t *buf = NULL;
    size_t buf_len = text_format_to_value(LWM2M_FLOAT, (const uint8_t*)value_buffer, value_length, &buf);
    CHECK(buf_len > 0);
    MEMCMP_EQUAL(bytes, buf, buf_len);
    free(buf);
}

TEST(edgeclient_scan_values, scan_uint8_t_float_with_extra_before)
{
    const char value_buffer[] = "a1.23456";
    const uint32_t value_length = sizeof(value_buffer);
    uint8_t *buf = NULL;
    size_t buf_len = text_format_to_value(LWM2M_FLOAT, (const uint8_t*)value_buffer, value_length, &buf);
    CHECK(buf_len == 0);
    CHECK(buf == NULL);
}

TEST(edgeclient_scan_values, scan_uint8_t_float_with_extra_after)
{
    uint8_t bytes[8] = {0x40, 0x9E, 0xDD, 0x2F,
                        0x1A, 0x9F, 0xBE, 0x77};
    const char value_buffer[] = "1975.296a";
    const uint32_t value_length = sizeof(value_buffer);
    uint8_t *buf = NULL;
    size_t buf_len = text_format_to_value(LWM2M_FLOAT, (const uint8_t*)value_buffer, value_length, &buf);
    CHECK(buf_len > 0);
    MEMCMP_EQUAL(bytes, buf, buf_len);
    free(buf);
}

TEST(edgeclient_scan_values, test_scan_integer_extra_before)
{
    const char value_buffer[] = "a100";
    const uint32_t value_length = sizeof(value_buffer);
    uint8_t *buf = NULL;
    size_t buf_len = text_format_to_value(LWM2M_INTEGER, (const uint8_t*)value_buffer, value_length, &buf);
    CHECK(buf_len == 0);
    CHECK(buf == NULL);
}

TEST(edgeclient_scan_values, test_scan_integer_extra_after)
{
    uint8_t bytes[8] = {0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x64};
    const char value_buffer[] = "100a";
    const uint32_t value_length = sizeof(value_buffer);
    uint8_t *buf = NULL;
    size_t buf_len = text_format_to_value(LWM2M_INTEGER, (const uint8_t*)value_buffer, value_length, &buf);
    CHECK(buf_len > 0);
    MEMCMP_EQUAL(bytes, buf, buf_len);
    free(buf);
}

TEST(edgeclient_scan_values, test_scan_bool_extra_before)
{
    // val = true
    const char value_buffer[] = "a1";
    const uint32_t value_length = sizeof(value_buffer);
    uint8_t *buf = NULL;
    size_t buf_len = text_format_to_value(LWM2M_BOOLEAN, (const uint8_t*)value_buffer, value_length, &buf);
    CHECK(buf_len == 0);
    CHECK(buf == NULL);
}

TEST(edgeclient_scan_values, test_scan_bool_extra_after)
{
    uint8_t bytes[1] = {0x00};
    const char value_buffer[] = "0a";
    const uint32_t value_length = sizeof(value_buffer);
    uint8_t *buf = NULL;
    size_t buf_len = text_format_to_value(LWM2M_BOOLEAN, (const uint8_t*)value_buffer, value_length, &buf);
    CHECK(buf_len == 1);
    MEMCMP_EQUAL(bytes, buf, buf_len);
    free(buf);
}

TEST(edgeclient_scan_values, test_scan_time)
{
    uint8_t bytes[8] = {0x00, 0x00, 0x00, 0x02,
                        0xDF, 0xDC, 0x1C, 0x35};
    const char value_buffer[] = "12345678901";
    const uint32_t value_length = sizeof(value_buffer);
    uint8_t *buf = NULL;
    size_t buf_len = text_format_to_value(LWM2M_TIME, (const uint8_t*)value_buffer, value_length, &buf);
    CHECK(buf_len > 0);
    MEMCMP_EQUAL(bytes, buf, buf_len);
    free(buf);
}

TEST(edgeclient_scan_values, test_scan_string)
{
    const char value_buffer[] = "string";
    const uint32_t value_length = sizeof(value_buffer);
    uint8_t *buf = NULL;
    size_t buf_len = text_format_to_value(LWM2M_STRING, (const uint8_t*)value_buffer, value_length, &buf);
    CHECK(buf_len == value_length);
    MEMCMP_EQUAL(value_buffer, buf, buf_len);
    free(buf);
}

TEST(edgeclient_scan_values, test_scan_opaque)
{
    const char value_buffer[] = "\255opa\0que";
    const uint32_t value_length = sizeof(value_buffer);
    uint8_t *buf = NULL;
    size_t buf_len = text_format_to_value(LWM2M_OPAQUE, (const uint8_t*)value_buffer, value_length, &buf);
    CHECK(buf_len == value_length);
    MEMCMP_EQUAL(value_buffer, buf, buf_len);
    free(buf);
}

TEST(edgeclient_scan_values, test_scan_objlink)
{
    const char value_buffer[] = "1:0";
    const uint32_t value_length = sizeof(value_buffer);
    uint8_t *buf = NULL;
    size_t buf_len = text_format_to_value(LWM2M_OBJLINK, (const uint8_t*)value_buffer, value_length, &buf);
    CHECK(buf_len == value_length);
    MEMCMP_EQUAL(value_buffer, buf, buf_len);
    free(buf);
}
