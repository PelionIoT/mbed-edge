#include <stdlib.h>
#include <stdint.h>
#include "CppUTest/TestHarness.h"

extern "C" {
#include "common/default_message_id_generator.h"
}

TEST_GROUP(default_message_id_generator) {
    void setup()
    {
    }

    void teardown()
    {
    }
};

TEST(default_message_id_generator, test_generation_for_first_10K_values)
{
    int32_t i;
    for (i = 0; i < 10000; i++) {
        char* id = edge_default_generate_msg_id();
        CHECK_EQUAL(i, atoi(id));
        free(id);
    }
}
