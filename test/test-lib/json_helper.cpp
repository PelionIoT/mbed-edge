/*
 * ----------------------------------------------------------------------------
 * Copyright 2018 ARM Ltd.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ----------------------------------------------------------------------------
 */

#include "CppUTest/TestHarness.h"
#include "CppUTestExt/MockSupport.h"
#include <jansson.h>
extern "C" {
#include "test-lib/json_helper.h"
#define JSON_BUFFER_MAX_SIZE 4096


json_t* load_json_params(const char *filepath)
{
    FILE *fh;
    size_t json_buffer_size = 0;
    char json_buffer[JSON_BUFFER_MAX_SIZE];
    fh = fopen(filepath, "r");
    json_buffer_size = fread(json_buffer, sizeof(char), JSON_BUFFER_MAX_SIZE, fh);
    fclose(fh);
    if (json_buffer_size > JSON_BUFFER_MAX_SIZE) {
        FAIL("JSON buffer not big enough!");
    }
    // NULL terminate json buffer
    json_buffer[json_buffer_size] = 0;
    // Load json buffer into structure
    json_error_t json_error;
    json_t *params = NULL;
    params = json_loads(json_buffer, 0, &json_error);
    if (params == NULL) {
        printf("\r\n%s:%d, col %d, pos %d\r\n", json_error.source, json_error.line, json_error.column, json_error.position);
        printf("Loading json from file got error: %s", json_error.text);
        FAIL("Loading json failed!");
    }
    return params;
}

} // extern "C"
