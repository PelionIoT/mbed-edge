/* SPDX-License-Identifier: Apache-2.0 */
#ifndef EDGE_MACOS_NETWORK_CONFIG_H
#define EDGE_MACOS_NETWORK_CONFIG_H
#include <CoreFoundation/CoreFoundation.h>
#include <stddef.h>
/* Internal signal: inspect current configuration without forcing a reconnect. */
#define EDGE_MACOS_NETWORK_RECHECK 32u
/* Returns a newly owned, normalized snapshot; NULL means inspection failed. */
CFDictionaryRef edge_macos_network_snapshot(CFDictionaryRef values);
/* Parses notification bytes without accessing unaligned Darwin structures. */
unsigned edge_macos_network_route_changes(const void *data, size_t length);
#endif
