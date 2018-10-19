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

#define TRACE_GROUP "edgecc"

#include <stdlib.h>
#include "common/constants.h"
#include "edge-client/edge_client_format_values.h"
#include "mbed-trace/mbed_trace.h"
#include "common/test_support.h"

size_t integer_to_text_format(int32_t value, char *buffer, size_t buffer_len)
{
    return snprintf(buffer, buffer_len, "%d", value);
}

size_t long_integer_to_text_format(int64_t value, char *buffer, size_t buffer_len)
{
    return snprintf(buffer, buffer_len, "%" PRId64 "", value);
}

size_t float_to_text_format(float value, char *buffer, size_t buffer_len)
{
    return snprintf(buffer, buffer_len, "%6.9f", value);
}

size_t double_to_text_format(double value, char *buffer, size_t buffer_len)
{
    return snprintf(buffer, buffer_len, "%10.17f", value);
}

size_t bool_to_text_format(bool value, char *buffer, size_t buffer_len)
{
    return snprintf(buffer, buffer_len, "%d", value);
}

void convert_to_int32_t(const uint8_t *value, const size_t value_length, int32_t *number)
{
    if (value_length == sizeof(int8_t)) {
        int8_t temp = 0;
        memcpy(&temp, value, value_length);
        *number = temp;
    } else if (value_length == sizeof(int16_t)) {
        int16_t temp = 0;
        memcpy(&temp, value, value_length);
        temp = ntohs(temp);
        *number = temp;
    } else {
        *number = common_read_32_bit(value);
    }
}

void convert_to_int64_t(const uint8_t *value, const size_t value_length, int64_t *number)
{
    if (value_length == sizeof(int64_t)) {
        *number = common_read_64_bit(value);
    }
}

void convert_to_float(const uint8_t *value, const size_t value_length, float *number)
{
    uint32_t temp = common_read_32_bit(value);
    memcpy(number, &temp, sizeof(float));
}

void convert_to_double(const uint8_t *value, const size_t value_length, double *number)
{
    if (value_length == sizeof(double)) {
        uint64_t temp = common_read_64_bit(value);
        memcpy(number, &temp, sizeof(double));
    }
}

static bool text_format_scan_64bit_numeric_value(const uint8_t *text_buffer,
                                                 const uint32_t text_length,
                                                 uint64_t *value,
                                                 Lwm2mResourceType value_type);

size_t value_to_text_format(Lwm2mResourceType resource_type, const uint8_t* value,
                            const uint32_t value_length, char** buffer)
{
    if (value && value_length > 0) {
        size_t size;
        int32_t converted_integer = 0;
        int64_t converted_long_integer = 0;
        float converted_float = 0;
        double converted_double = 0;
        switch (resource_type) {
            /* Time is essentially an integer */
            case LWM2M_TIME:
            case LWM2M_INTEGER:
                if (value_length == sizeof(int8_t) || value_length == sizeof(int16_t) ||
                    value_length == sizeof(int32_t)) {
                    /* Convert the integer type to uint32_t from uint8_t data */
                    convert_to_int32_t(value, value_length, &converted_integer);
                    /* Calculate the needed buffer size first */
                    size = integer_to_text_format(converted_integer, NULL, 0);
                    if (!buffer) {
                        return size;
                    }
                    *buffer = (char*) calloc(size + 1, sizeof(char));
                    if (*buffer == NULL) {
                        tr_err("Could not allocate buffer for integer format");
                        break;
                    }
                    return integer_to_text_format(converted_integer, *buffer, size + 1);
                } else if (value_length == sizeof(int64_t)) {
                    convert_to_int64_t(value, value_length, &converted_long_integer);
                    size = long_integer_to_text_format(converted_long_integer, NULL, 0);
                    if (!buffer) {
                        return size;
                    }
                    *buffer = (char*) calloc(size + 1, sizeof(char));
                    if (*buffer == NULL) {
                        tr_err("Could not allocate buffer for long integer format");
                        break;
                    }
                    return long_integer_to_text_format(converted_long_integer, *buffer, size + 1);
                } else {
                    tr_err("LWM2M integer value length illegal: %d.", value_length);
                }
                break;
            case LWM2M_FLOAT:
                if (value_length == sizeof(float)) {
                    convert_to_float(value, value_length, &converted_float);
                    size = float_to_text_format(converted_float, NULL, 0);
                    if (!buffer) {
                        return size;
                    }
                    *buffer = (char*) calloc(size + 1, sizeof(char));
                    if (*buffer == NULL) {
                        tr_err("Could not allocate buffer for float format");
                        break;
                    }
                    return float_to_text_format(converted_float, *buffer, size + 1);
                } else if (value_length == sizeof(double)) {
                    convert_to_double(value, value_length, &converted_double);
                    size = double_to_text_format(converted_double, NULL, 0);
                    if (!buffer) {
                        return size;
                    }
                    *buffer = (char*) calloc(size + 1, sizeof(char));
                    if (*buffer == NULL) {
                        tr_err("Could not allocate buffer for double format");
                        break;
                    }
                    return double_to_text_format(converted_double, *buffer, size + 1);
                } else {
                    tr_err("LWM2M float value length illegal: %d.", value_length);
                }
                break;
            case LWM2M_BOOLEAN:
                /* Convert the integer type to uint32_t from uint8_t data */
                /* Boolean value must always be 1 byte. */
                if (value_length == sizeof(uint8_t)) {
                    size = bool_to_text_format((bool) *value, NULL, 0);
                    if (!buffer) {
                        return size;
                    }
                    *buffer = (char*) calloc(size + 1, sizeof(char));
                    if (*buffer == NULL) {
                        tr_err("Could not allocate buffer for boolean format");
                        break;
                    }
                    return bool_to_text_format((bool) *value, *buffer, size + 1);
                } else {
                    tr_err("LWM2M boolean value length illegal: %d.", value_length);
                }
                break;
            case LWM2M_STRING:
            case LWM2M_OPAQUE:
            case LWM2M_OBJLINK:
            default:
                /* For string, opaque and objlink just pass the value */
                if (!buffer) {
                    return value_length;
                }
                *buffer = (char*) calloc(value_length, sizeof(uint8_t));
                if (*buffer == NULL) {
                    tr_err("Could not allocate buffer for string format");
                    break;
                }
                memcpy(*buffer, value, value_length);
                return value_length;
        }
    }
    if (buffer) {
        *buffer = NULL;
    }
    return 0;
}

size_t text_format_to_value(Lwm2mResourceType resource_type, const uint8_t* value,
                            const uint32_t value_length, uint8_t** buffer)
{
    size_t len = 0;

    if (buffer == NULL || value == NULL || value_length == 0) {
        return 0;
    }

    if (resource_type == LWM2M_STRING || resource_type == LWM2M_OPAQUE || resource_type == LWM2M_OBJLINK) {
        /* For string, opaque and objlink just copy the value */
        len = value_length;
        *buffer = (uint8_t*) calloc(len, sizeof(uint8_t));
        if (*buffer == NULL) {
            return 0;
        }
        memcpy(*buffer, value, len);
    }
    else if (resource_type == LWM2M_BOOLEAN) {
        /* Boolean should be either '0' or '1' so just compare rather than scanf */
        uint8_t bool_value = 0;
        if (value[0] == '0') {
            bool_value = 0;
        }
        else if (value[0] == '1') {
            bool_value = 1;
        }
        else {
          return 0;
        }
        /* LWM2M boolean is single byte */
        len = sizeof(uint8_t);
        *buffer = (uint8_t*)calloc(len, sizeof(uint8_t));
        if (*buffer == NULL) {
            return 0;
        }
        **buffer = bool_value;
    }
    else {
        /* LWM2M_TIME, LWM2M_INTEGER and LWM2M_FLOAT */
        uint64_t scanned_value = 0;
        if (!text_format_scan_64bit_numeric_value(value, value_length, &scanned_value, resource_type)) {
          return 0;
        }
        len = sizeof(uint64_t);
        *buffer = (uint8_t*)calloc(len, sizeof(uint8_t));
        if (*buffer == NULL) {
          return 0;
        }
        common_write_64_bit(scanned_value, *buffer);
    }
    return len;

}

#define SCAN_FMTBUF_LEN 6

static bool text_format_scan_double_value(const uint8_t *text_buffer, const uint32_t text_length,
                                          double *value) {
    uint8_t *endptr = NULL;

    *value = strtod((const char*)text_buffer, (char**)&endptr);

    if (endptr == text_buffer) {
        // No valid floating point number
        return false;
    }

    return true;
}

static bool text_format_scan_integer_value(const uint8_t *text_buffer, const uint32_t text_length,
                                           uint64_t *value) {
    uint8_t *endptr = NULL;

    *value = strtol((const char*)text_buffer, (char**)&endptr, 10);

    if (endptr == text_buffer) {
        // No valid integer number
        return false;
    }

    return true;
}

static bool text_format_scan_64bit_numeric_value(const uint8_t *text_buffer,
                                                 const uint32_t text_length,
                                                 uint64_t *value,
                                                 Lwm2mResourceType value_type) {
  if (value_type == LWM2M_INTEGER || value_type == LWM2M_TIME) {
      return text_format_scan_integer_value(text_buffer, text_length, value);
  }
  else {
    return text_format_scan_double_value(text_buffer, text_length, (double*)value);
  }
  return false;
}
