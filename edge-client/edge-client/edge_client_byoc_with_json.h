/*
 * Copyright (c) 2025 Izuma Networks Inc
 *
 * This file is licensed under the Limited Revocable Evaluation License.
 * Use of this source code is subject to the terms and conditions of the license.
 * See IZLREL_LICENSE.txt for full details.
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
