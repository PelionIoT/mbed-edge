/* SPDX-License-Identifier: Apache-2.0 */
#ifndef EDGE_WINDOWS_RUNTIME_CONFIG_H
#define EDGE_WINDOWS_RUNTIME_CONFIG_H
#include <stdbool.h>
#define EDGE_PIPE_NAME_CAPACITY 256
#define EDGE_PIPE_MAX_CLIENT_SIDS 16
#define EDGE_PIPE_SID_CAPACITY 192
typedef struct {
    bool tcp_enabled;
    char tcp_address[32];
    bool af_unix_enabled;
    char af_unix_path[108];
    bool named_pipe_enabled;
    char named_pipe_name[EDGE_PIPE_NAME_CAPACITY];
    unsigned named_pipe_max_clients;
    unsigned named_pipe_client_sid_count;
    char named_pipe_client_sids[EDGE_PIPE_MAX_CLIENT_SIDS][EDGE_PIPE_SID_CAPACITY];
} edge_runtime_config;
bool edge_runtime_pipe_name_valid(const char *name);
void edge_runtime_config_defaults(edge_runtime_config *config);
/* UTF-8 filename; reads startup settings, not cloud provisioning credentials. */
bool edge_runtime_config_load(edge_runtime_config *config, const char *filename);
#endif
