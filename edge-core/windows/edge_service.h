/* SPDX-License-Identifier: Apache-2.0 */
#ifndef EDGE_WINDOWS_SERVICE_H
#define EDGE_WINDOWS_SERVICE_H
#include <stdbool.h>
int edge_core_run(int argc, char **argv);
bool edge_core_request_stop(void);
bool edge_windows_service_mode(void);
void edge_windows_service_checkpoint(void);
bool edge_windows_service_ready(void);
#endif
