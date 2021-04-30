#include "CppUTest/TestHarness.h"
extern "C" {
#include "edge-client/edge_client_format_values.h"
}
#include <string.h>

TEST_GROUP(edgeclient_format_values) {
    void setup()
    {
    }

    void teardown()
    {
    }
};

TEST(edgeclient_format_values, test_format_integer_zero)
{
    size_t size = integer_to_text_format(0, NULL, 0);

    char *buffer = (char*) calloc(size + 1, sizeof(char));
    integer_to_text_format(0, buffer, size + 1);

    STRNCMP_EQUAL("0", buffer, 1);
    UNSIGNED_LONGS_EQUAL(1, size);
    free(buffer);
}

TEST(edgeclient_format_values, test_format_integer_100)
{
    size_t size = integer_to_text_format(100, NULL, 0);

    char *buffer = (char*) calloc(size + 1, sizeof(char));
    integer_to_text_format(100, buffer, size + 1);

    STRNCMP_EQUAL("100", buffer, 3);
    UNSIGNED_LONGS_EQUAL(3, size);
    free(buffer);
}

TEST(edgeclient_format_values, test_format_negative_integer)
{
    size_t size = integer_to_text_format(-1, NULL, 0);

    char *buffer = (char*) calloc(size + 1, sizeof(char));
    integer_to_text_format(-1, buffer, size + 1);

    STRNCMP_EQUAL("-1", buffer, 2);
    UNSIGNED_LONGS_EQUAL(2, size);
    free(buffer);
}

TEST(edgeclient_format_values, test_format_float_zero)
{
    size_t size = float_to_text_format(0.0, NULL, 0);

    char *buffer = (char*) calloc(size + 1, sizeof(char));
    float_to_text_format(0.0, buffer, size + 1);

    STRNCMP_EQUAL("0.000000000", buffer, 3);
    free(buffer);
}

TEST(edgeclient_format_values, test_format_float_101_and_bit_more)
{
    size_t size = float_to_text_format(101.12, NULL, 0);

    char *buffer = (char*) calloc(size + 1, sizeof(char));
    float_to_text_format(101.12, buffer, size + 1);

    STRNCMP_EQUAL("101.120002747", buffer, 14);
    free(buffer);
}

TEST(edgeclient_format_values, test_format_negative_float)
{
    size_t size = float_to_text_format(-3.21, NULL, 0);

    char *buffer = (char*) calloc(size + 1, sizeof(char));
    float_to_text_format(-3.21, buffer, size + 1);

    STRNCMP_EQUAL("-3.210000038", buffer, 12);
    free(buffer);
}

TEST(edgeclient_format_values, test_format_high_precision_float)
{
    float HIGH_PRECISION = 0.0123456789;
    size_t size = float_to_text_format(-3.21, NULL, 0);

    char *buffer = (char*) calloc(size + 1, sizeof(char));
    float_to_text_format(HIGH_PRECISION, buffer, size + 1);

    STRNCMP_EQUAL("0.012345679", buffer, 12);
    free(buffer);
}

TEST(edgeclient_format_values, test_format_double_zero)
{
    size_t size = double_to_text_format(0.0, NULL, 0);

    char *buffer = (char*) calloc(size + 1, sizeof(char));
    double_to_text_format(0.0, buffer, size + 1);

    STRNCMP_EQUAL("0.00000000000000000", buffer, 20);
    free(buffer);
}

TEST(edgeclient_format_values, test_format_double_101_and_bit_more)
{
    size_t size = double_to_text_format(101.12, NULL, 0);

    char *buffer = (char*) calloc(size + 1, sizeof(char));
    double_to_text_format(101.12, buffer, size + 1);

    STRNCMP_EQUAL("101.12000000000000455", buffer, 20);
    free(buffer);
}

TEST(edgeclient_format_values, test_format_negative_double)
{
    size_t size = double_to_text_format(-3.21, NULL, 0);

    char *buffer = (char*) calloc(size + 1, sizeof(char));
    double_to_text_format(-3.21, buffer, size + 1);

    STRNCMP_EQUAL("-3.20999999999999996", buffer, 20);
    free(buffer);
}

TEST(edgeclient_format_values, test_format_high_precision_double)
{
    double HIGH_PRECISION = 0.01234567890123456;
    size_t size = double_to_text_format(HIGH_PRECISION, NULL, 0);

    char *buffer = (char*) calloc(size + 1, sizeof(char));
    double_to_text_format(HIGH_PRECISION, buffer, size + 1);

    STRNCMP_EQUAL("0.01234567890123456", buffer, 20);
    free(buffer);
}

TEST(edgeclient_format_values, test_bool_true)
{
    size_t size = bool_to_text_format(true, NULL, 0);

    char *buffer = (char*) calloc(size + 1, sizeof(char));
    bool_to_text_format(true, buffer, size + 1);

    STRNCMP_EQUAL("1", buffer, 1);
    free(buffer);
}

TEST(edgeclient_format_values, test_bool_false)
{
    size_t size = bool_to_text_format(false, NULL, 0);

    char *buffer = (char*) calloc(size + 1, sizeof(char));
    bool_to_text_format(false, buffer, size + 1);

    STRNCMP_EQUAL("0", buffer, 1);
    free(buffer);
}

TEST(edgeclient_format_values, convert_uint8_t_tiny)
{
    uint8_t bytes[1] = {0x55};
    int32_t expected = 85;
    int32_t result = 0;
    convert_to_int32_t(bytes, sizeof(int8_t), &result);
    LONGS_EQUAL(expected, result);
}

TEST(edgeclient_format_values, convert_uint8_t_negative_tiny)
{
    uint8_t bytes[1] = {0xF4};
    int32_t expected = -12;
    int32_t result = 0;
    convert_to_int32_t(bytes, sizeof(int8_t), &result);
    LONGS_EQUAL(expected, result);
}

TEST(edgeclient_format_values, convert_uint8_t_small)
{
    uint8_t bytes[2] = {0x7F, 0xFF};
    int32_t expected = 32767;
    int32_t result = 0;
    convert_to_int32_t(bytes, sizeof(int16_t), &result);
    LONGS_EQUAL(expected, result);
}

TEST(edgeclient_format_values, convert_uint8_t_negative_small)
{
    uint8_t bytes[2] = {0x80, 0x01};
    int32_t expected = -32767;
    int32_t result = 0;
    convert_to_int32_t(bytes, sizeof(int16_t), &result);
    LONGS_EQUAL(expected, result);
}

TEST(edgeclient_format_values, convert_uint8_t_large)
{
    uint8_t bytes[4] = {0x14, 0x95, 0x8D, 0x41};
    int32_t expected = 345345345;
    int32_t result = 0;
    convert_to_int32_t(bytes, sizeof(int32_t), &result);
    LONGS_EQUAL(expected, result);
}

TEST(edgeclient_format_values, convert_uint8_t_negative_large)
{
    uint8_t bytes[4] = {0xF8, 0xA9, 0x4A, 0x4D};
    int32_t expected = -123123123;
    int32_t result = 0;
    convert_to_int32_t(bytes, sizeof(int32_t), &result);
    LONGS_EQUAL(expected, result);
}

TEST(edgeclient_format_values, convert_uint8_t_huge)
{
    uint8_t bytes[8] = {0x18, 0x7D, 0xE9, 0x99, 0xE8, 0x3A, 0x0D, 0xF1};
    int64_t expected = 1764823476234489329;
    int64_t result = 0;
    convert_to_int64_t(bytes, sizeof(int64_t), &result);
    LONGS_EQUAL(expected, result);
}

TEST(edgeclient_format_values, convert_uint8_t_float)
{
    uint8_t bytes[4] = {0x46, 0x4A, 0x28, 0x7E};
    float expected = 12938.123;
    float result = 0;
    convert_to_float(bytes, sizeof(float), &result);
    MEMCMP_EQUAL(&expected, &result, sizeof(float));
}

TEST(edgeclient_format_values, convert_uint8_t_negative_float)
{
    uint8_t bytes[4] = {0xC6, 0x4A, 0x28, 0x7E};
    float expected = -12938.123;
    float result = 0;
    convert_to_float(bytes, sizeof(float), &result);
    MEMCMP_EQUAL(&expected, &result, sizeof(float));
}

TEST(edgeclient_format_values, convert_uint8_t_double)
{
    uint8_t bytes[8] = {0x23, 0xFA, 0xDD, 0xDC, 0xAA, 0x52, 0xCE, 0xC1};
    double expected = 2.310231231290381e-135;
    double result = 0;
    convert_to_double(bytes, sizeof(double), &result);
    DOUBLES_EQUAL(expected, result, 17);
    MEMCMP_EQUAL(&expected, &result, sizeof(double));
}

TEST(edgeclient_format_values, convert_uint8_t_negative_double)
{
    uint8_t bytes[8] = {0xA3, 0xFA, 0xDD, 0xDC, 0xAA, 0x52, 0xCE, 0xC1};
    double expected = -2.310231231290381e-135;
    double result = 0;
    convert_to_double(bytes, sizeof(double), &result);
    DOUBLES_EQUAL(expected, result, 17);
    MEMCMP_EQUAL(&expected, &result, sizeof(double));
}
