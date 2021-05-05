#include <stdint.h>
#include <string.h>
#include "CppUTest/TestHarness.h"

extern "C" {
#include "common/integer_length.h"
}

uint16_t MAX_UINT32_T_LEN = strlen("4294967295");

TEST_GROUP(integer_length) {
    void setup()
    {
    }

    void teardown()
    {
    }
};

TEST(integer_length, test_negative_integer)
{
    /* this test checks that the algorithm does not fail
     * the signed integer is converted to unsigned integer
     * which will equal to uint32_t of 4294967196.
     */
    uint16_t len_of_unsigned = edge_int_length(4294967196);
    uint16_t len = edge_int_length(-100);
    CHECK_EQUAL(len_of_unsigned, len);
}

TEST(integer_length, test_zero)
{
    CHECK_EQUAL(1, edge_int_length(0));
}

TEST(integer_length, test_one)
{
    CHECK_EQUAL(1, edge_int_length(1));
}

TEST(integer_length, test_maximum_length)
{
    CHECK_EQUAL(MAX_UINT32_T_LEN, edge_int_length((uint32_t) -1));
}

TEST(integer_length, test_multiple_lengths)
{
    uint32_t num = 0;
    uint32_t factor = 10;
    uint32_t current_factor = 10;
    for(int i = 1; i < 10; i++) {
        if (i < 9) {
            num = i * current_factor;
        } else {
            /* Must cap the uint32_t here, on the 9th round it will overflow
             * if multiplied with 10
             */
            num = (uint32_t) -1;
        }
        CHECK_EQUAL(i + 1, edge_int_length(num));
        current_factor = current_factor * factor;
    }
}
