/* Windows defaults selected through PAL_PLATFORM_DEFINED_CONFIGURATION.
 * The remaining settings come from PAL's platform-independent defaults.
 */
#ifndef PAL_WINDOWS_CONFIGURATION_H
#define PAL_WINDOWS_CONFIGURATION_H

#define PAL_NUMBER_OF_PARTITIONS 1
#define PAL_NET_MAX_IF_NAME_LENGTH 256
#define PAL_NET_DNS_SUPPORT 1
#define PAL_USE_FILESYSTEM 1
#ifndef PAL_DNS_API_VERSION
/* Use PAL's existing asynchronous DNS worker around the platform resolver. */
#define PAL_DNS_API_VERSION 1
#endif
#define PAL_NET_ASYNC_DNS_THREAD_STACK_SIZE (128 * 1024)

#endif
