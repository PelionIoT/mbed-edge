/* SPDX-License-Identifier: Apache-2.0 */
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/route.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "../edge_network_recovery.h"
#include "edge_network_config.h"

CFDictionaryRef edge_macos_network_snapshot(CFDictionaryRef values)
{
    if (!values || CFGetTypeID(values) != CFDictionaryGetTypeID()) return NULL;
    CFIndex count = CFDictionaryGetCount(values);
    if (count < 0 || count > 4096) return NULL;
    const void **keys = calloc((size_t)count + 1, sizeof(*keys));
    const void **entries = calloc((size_t)count + 1, sizeof(*entries));
    if (!keys || !entries) { free(keys); free(entries); return NULL; }
    CFDictionaryGetKeysAndValues(values, keys, entries);
    CFMutableDictionaryRef snapshot = CFDictionaryCreateMutable(NULL, 0,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    /* Public network entity properties only: exclude DHCP lease timestamps,
     * counters and other operational metadata that do not change a path. */
    const CFStringRef fields[] = {
        CFSTR("ServerAddresses"), CFSTR("ServerPort"), CFSTR("DomainName"),
        CFSTR("SearchDomains"), CFSTR("SupplementalMatchDomains"),
        CFSTR("SupplementalMatchOrders"), CFSTR("SearchOrder"), CFSTR("Options"),
        CFSTR("ServerTimeout"), CFSTR("InterfaceIndex"), CFSTR("ScopedQuery"),
        CFSTR("Addresses"), CFSTR("SubnetMasks"), CFSTR("DestAddresses"),
        CFSTR("PrefixLength"), CFSTR("Router"), CFSTR("InterfaceName"),
        CFSTR("PrimaryInterface"), CFSTR("PrimaryService"),
        CFSTR("AdditionalRoutes"), CFSTR("ExcludedRoutes"),
        CFSTR("Active"), CFSTR("Detaching")
    };
    for (CFIndex i = 0; i < count; ++i) {
        if (CFGetTypeID(keys[i]) != CFStringGetTypeID() ||
            CFGetTypeID(entries[i]) != CFDictionaryGetTypeID()) continue;
        CFMutableDictionaryRef entity = CFDictionaryCreateMutable(NULL, 0,
            &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        for (size_t f = 0; f < sizeof(fields) / sizeof(fields[0]); ++f) {
            CFTypeRef value = CFDictionaryGetValue(entries[i], fields[f]);
            if (value) CFDictionarySetValue(entity, fields[f], value);
        }
        /* Ignore empty metadata-only records and their removal. */
        if (CFDictionaryGetCount(entity)) CFDictionarySetValue(snapshot, keys[i], entity);
        CFRelease(entity);
    }
    free(keys); free(entries);
    return snapshot;
}

unsigned edge_macos_network_route_changes(const void *data, size_t length)
{
    if (!data && length) return EDGE_MACOS_NETWORK_RECHECK;
    const unsigned char *cursor = data;
    unsigned changes = 0;
    while (length) {
        struct { uint16_t length; uint8_t version, type; } header;
        if (length < sizeof(header)) return changes | EDGE_MACOS_NETWORK_RECHECK;
        memcpy(&header, cursor, sizeof(header));
        if (header.length < sizeof(header) || header.length > length)
            return changes | EDGE_MACOS_NETWORK_RECHECK;
        if (header.version == RTM_VERSION) {
            switch (header.type) {
                case RTM_ADD: case RTM_DELETE: case RTM_CHANGE: {
                    if (header.length < sizeof(struct rt_msghdr)) {
                        changes |= EDGE_MACOS_NETWORK_RECHECK;
                        break;
                    }
                    struct rt_msghdr route;
                    memcpy(&route, cursor, sizeof(route));
                    int ignored = RTF_LLINFO;
#ifdef RTF_WASCLONED
                    ignored |= RTF_WASCLONED;
#endif
                    if (!route.rtm_errno && !(route.rtm_flags & ignored)) changes |= EDGE_NETWORK_ROUTE;
                    break;
                }
                case RTM_NEWADDR: case RTM_DELADDR:
                    changes |= EDGE_NETWORK_ADDRESS;
                    break;
                case RTM_IFINFO:
                    /* Interface counters also generate IFINFO; inspect Link
                     * and IP configuration rather than resetting on traffic. */
                    changes |= EDGE_MACOS_NETWORK_RECHECK;
                    break;
                default: break;
            }
        }
        cursor += header.length; length -= header.length;
    }
    return changes;
}
