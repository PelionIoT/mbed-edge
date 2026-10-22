/* SPDX-License-Identifier: Apache-2.0 */
#ifndef PROTOCOL_CREDENTIAL_API_H
#define PROTOCOL_CREDENTIAL_API_H
#include <jansson.h>
#include <stdbool.h>
void credential_api_protocol_init(void);
bool credential_api_provision(const char *path);
int credential_api_open(json_t *request, json_t *params, json_t **result, void *userdata);
int credential_api_request(json_t *request, json_t *params, json_t **result, void *userdata);
#endif
