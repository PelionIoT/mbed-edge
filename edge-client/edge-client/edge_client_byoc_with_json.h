/*
 * Copyright (c) 2025 Izuma Networks Inc
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
 */

#ifdef MBED_EDGE_ENABLE_BYOC_JSON

#ifndef EDGE_CLIENT_BYOC_H_
#define EDGE_CLIENT_BYOC_H_

typedef struct
{
    const char *cbor_file;
    const char *json_file;
} byoc_data_t;

byoc_data_t *edgeclient_create_byoc_data(char *cbor_file, char *json_file);
void edgeclient_destroy_byoc_data(byoc_data_t *byoc_data);
int edgeclient_inject_byoc(byoc_data_t *byoc_data);

#endif /* EDGE_CLIENT_BYOC_H_ */

#endif // MBED_EDGE_ENABLE_BYOC_JSON
