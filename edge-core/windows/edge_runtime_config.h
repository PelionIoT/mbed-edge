/* SPDX-License-Identifier: Apache-2.0 */
#ifndef EDGE_WINDOWS_RUNTIME_CONFIG_H
#define EDGE_WINDOWS_RUNTIME_CONFIG_H
#include <stdbool.h>
typedef struct {
    char tcp_address[32];
    bool af_unix_enabled;
    char af_unix_path[108];
} edge_runtime_config;
void edge_runtime_config_defaults(edge_runtime_config *config);
/* UTF-8 filename; reads startup settings, not cloud provisioning credentials. */
bool edge_runtime_config_load(edge_runtime_config *config, const char *filename);
#endif
