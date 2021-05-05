#include "CppUTest/TestHarness.h"

#include <arpa/inet.h>
#include <string.h>
extern "C" {
#include "edge-client/edge_client_format_values.h"
}

#include "edge-client/edge_client_internal.h"
#include "common_functions.h"

TEST_GROUP(edgeclient_format_values_by_type) {
    void setup()
    {
    }

    void teardown()
    {
    }
};

TEST(edgeclient_format_values_by_type, format_null_value)
{
    char* buffer;
    size_t size = value_to_text_format(LWM2M_INTEGER, NULL,
                                       sizeof(int8_t), &buffer);
    CHECK(0 == size);
    CHECK(NULL == buffer);
}

TEST(edgeclient_format_values_by_type, format_zero_length_value)
{
    int32_t value = 100;
    char* buffer;
    size_t size = value_to_text_format(LWM2M_INTEGER, (const uint8_t*) &value,
                                       0, &buffer);
    CHECK(0 == size);
    CHECK(NULL == buffer);
}

TEST(edgeclient_format_values_by_type, format_integer_8bits)
{
    int8_t value = 100;
    char* buffer;
    size_t size = value_to_text_format(LWM2M_INTEGER, (const uint8_t*) &value,
                                       sizeof(int8_t), &buffer);
    CHECK(size > 0);
    STRNCMP_EQUAL("100", buffer, 3);
    free(buffer);
}

TEST(edgeclient_format_values_by_type, format_integer_16bits)
{
    int16_t value = htons(32767);
    char* buffer;
    size_t size = value_to_text_format(LWM2M_INTEGER, (const uint8_t*) &value,
                                       sizeof(int16_t), &buffer);
    CHECK(size > 0);
    STRNCMP_EQUAL("32767", buffer, 5);
    free(buffer);
}

TEST(edgeclient_format_values_by_type, format_integer_32bits)
{
    int32_t value = ntohl(100);
    char* buffer;
    size_t size = value_to_text_format(LWM2M_INTEGER, (const uint8_t*) &value,
                                       sizeof(uint32_t), &buffer);
    CHECK(size > 0);
    STRNCMP_EQUAL("100", buffer, 3);
    free(buffer);
}

// formatting time also checks the case of converting 64 bit signed integer
TEST(edgeclient_format_values_by_type, format_time)
{
    int64_t original = 512872312456456423;
    uint64_t value = common_read_64_bit((const uint8_t*) &original);

    char* buffer;
    size_t size = value_to_text_format(LWM2M_TIME, (const uint8_t*) &value,
                                       sizeof(int64_t), &buffer);
    CHECK(size > 0);
    STRNCMP_EQUAL("512872312456456423", buffer, 3);
    free(buffer);
}

TEST(edgeclient_format_values_by_type, format_integer_illegal_size)
{
    uint8_t* odd_length_data = (uint8_t*) calloc(3, sizeof(uint8_t));
    char* buffer;
    size_t size = value_to_text_format(LWM2M_INTEGER, odd_length_data,
                                       3 * sizeof(uint8_t), &buffer);
    CHECK(0 == size);
    CHECK(NULL == buffer);
    free(odd_length_data);
}

TEST(edgeclient_format_values_by_type, format_float)
{
    float network_original = 1.5185e+35;
    uint8_t *data = (uint8_t*) calloc(1, sizeof(float));
    memcpy(data, &network_original, sizeof(float));

    char* buffer;
    size_t size = value_to_text_format(LWM2M_FLOAT, data,
                                       sizeof(float), &buffer);
    CHECK(size > 0);
    STRNCMP_EQUAL("1975.296020508", buffer, 14);
    free(buffer);
    free(data);
}

TEST(edgeclient_format_values_by_type, format_double)
{
    double network_original = -2.1200045354224807e+130;
    uint8_t *data = (uint8_t*) calloc(1, sizeof(double));
    memcpy(data, &network_original, sizeof(double));

    char* buffer;
    size_t size = value_to_text_format(LWM2M_FLOAT, data,
                                       sizeof(double), &buffer);
    CHECK(size > 0);
    STRNCMP_EQUAL("-9.22880999999999929", buffer, 20);
    free(buffer);
    free(data);
}

TEST(edgeclient_format_values_by_type, format_float_illegal_size)
{
    uint8_t* odd_length_data = (uint8_t*) calloc(3, sizeof(uint8_t));
    char* buffer;
    size_t size = value_to_text_format(LWM2M_FLOAT, odd_length_data,
                                       3 * sizeof(uint8_t), &buffer);
    CHECK(0 == size);
    CHECK(NULL == buffer);
    free(odd_length_data);
}

TEST(edgeclient_format_values_by_type, format_false_boolean)
{
    bool value = 0;
    char* buffer;
    size_t size = value_to_text_format(LWM2M_BOOLEAN, (const uint8_t*) &value,
                                       sizeof(bool), &buffer);
    CHECK(size > 0);
    STRNCMP_EQUAL("0", buffer, 1);
    free(buffer);
}

TEST(edgeclient_format_values_by_type, format_boolean_illegal_size)
{
    uint8_t* odd_length_data = (uint8_t*) calloc(3, sizeof(uint8_t));
    char* buffer;
    size_t size = value_to_text_format(LWM2M_BOOLEAN, odd_length_data,
                                       3 * sizeof(uint8_t), &buffer);
    CHECK(0 == size);
    CHECK(NULL == buffer);
    free(odd_length_data);
}

TEST(edgeclient_format_values_by_type, format_true_boolean)
{
    bool value = 1;
    char* buffer;
    size_t size = value_to_text_format(LWM2M_BOOLEAN, (const uint8_t*) &value,
                                       sizeof(bool), &buffer);
    CHECK(size > 0);
    STRNCMP_EQUAL("1", buffer, 1);
    free(buffer);
}

TEST(edgeclient_format_values_by_type, format_string)
{
    const char* value = "Test string";
    char* buffer;
    size_t size = value_to_text_format(LWM2M_STRING, (const uint8_t*) value,
                                       strlen(value), &buffer);
    CHECK(size > 0);
    STRNCMP_EQUAL("Test string", buffer, strlen("Test string"));
    free(buffer);
}

TEST(edgeclient_format_values_by_type, format_opaque)
{
    const char* value = "Opaque test string";
    char* buffer;
    size_t size = value_to_text_format(LWM2M_OPAQUE, (const uint8_t*) value,
                                       strlen(value), &buffer);
    CHECK(size > 0);
    STRNCMP_EQUAL("Opaque test string", buffer, strlen("Opaque test string"));
    free(buffer);
}

TEST(edgeclient_format_values_by_type, format_objlink)
{
    const char* value = "objlink";
    char* buffer;
    size_t size = value_to_text_format(LWM2M_OBJLINK, (const uint8_t*) value,
                                       strlen(value), &buffer);
    CHECK(size > 0);
    STRNCMP_EQUAL("objlink", buffer, strlen("objlink"));
    free(buffer);
}
