# Toolchain must add the target device and following
# definitions for the target platform.
# By default if not set the build is done for standard
# desktop Linux.

# Options

# Enable firmware update capabilities
option (FIRMWARE_UPDATE "Enable firware update" ON)

# Provisioning mode
# Use -D[DEVELOPER|BYOC|FACTORY]_MODE=ON
option (DEVELOPER_MODE "Developer mode" OFF)
option (BYOC_MODE "Bring your own certificate" OFF)
option (FACTORY_MODE "Factory provisioning" OFF)

# Trace CoAP payload
option (TRACE_COAP_PAYLOAD "Debug trace CoAP payload" OFF)

# Options end

# Set developer mode on as default if nothing is set from command line.
if (NOT ${DEVELOPER_MODE} AND NOT ${BYOC_MODE} AND NOT ${FACTORY_MODE})
  MESSAGE ("Defaulting to developer mode")
  SET (DEVELOPER_MODE ON)
endif()

# Mandatory definitions for Device Management Client
add_definitions ("-DRESOURCE_ATTRIBUTES_LIST=1")
add_definitions ("-DENABLE_ASYNC_REST_RESPONSE")

# Setting JSON RPC request time-outs

# Edge Core
SET (EDGE_SERVER_TIMEOUT_CHECK_INTERVAL_MS 5000)     # 5 seconds
SET (EDGE_SERVER_REQUEST_TIMEOUT_THRESHOLD_MS 60000) # one minute

# PT Client V2
SET (EDGE_CLIENT_TIMEOUT_CHECK_INTERVAL_MS 5000)     # 5 seconds
SET (EDGE_CLIENT_REQUEST_TIMEOUT_THRESHOLD_MS 60000) # one minute

# Select provisioning mode
if (${DEVELOPER_MODE})
  MESSAGE ("Developer mode provisioning set.")
  add_definitions ("-DDEVELOPER_MODE=1")
  add_definitions ("-DBIND_TO_ALL_INTERFACES=1")
  # Set trace on by default for developer mode
  add_definitions ("-DMBED_CONF_MBED_TRACE_ENABLE=1")
  if (NOT DEFINED MBED_CLOUD_IDENTITY_CERT_FILE)
    MESSAGE ("No external MBED_CLOUD_IDENTITY_CERT_FILE injected.")
    SET (MBED_CLOUD_IDENTITY_CERT_FILE "${CMAKE_CURRENT_SOURCE_DIR}/config/mbed_cloud_dev_credentials.c")
  else()
    MESSAGE ("Device Management developer certificate identity file injected.")
  endif()

  if (NOT ${TARGET_GROUP} STREQUAL test)
        MESSAGE ("Setting the identity cert file to \"${MBED_CLOUD_IDENTITY_CERT_FILE}\"")
    add_library (mbed-developer-certificate ${MBED_CLOUD_IDENTITY_CERT_FILE})
  endif()
elseif (${BYOC_MODE})
  MESSAGE ("BYOC mode provisioning set.")
  add_definitions ("-DBYOC_MODE=1")
elseif (${FACTORY_MODE})
  MESSAGE ("Factory mode provisioning set.")
else()
  MESSAGE (FATAL_ERROR "Unknown provisioning mode")
endif()

if (TRACE_COAP_PAYLOAD)
  MESSAGE ("Enabling CoAP payload debug printing.")
  add_definitions ("-DMBED_CLIENT_PRINT_COAP_PAYLOAD=1")
endif()

add_definitions ("-D__LINUX__")
add_definitions ("-DTARGET_IS_PC_LINUX")

if (NOT DEFINED TARGET_CONFIG_ROOT)
   include ("cmake/targets/default.cmake")
else ()
   include ("${TARGET_CONFIG_ROOT}/target.cmake")
endif()


if (${FIRMWARE_UPDATE})
  MESSAGE ("Enabling firmware update for Edge")
  if (${DEVELOPER_MODE})
    if (NOT DEFINED MBED_UPDATE_RESOURCE_FILE)
      MESSAGE ("The custom update resource descriptor c-file not injected.")
      SET (MBED_UPDATE_RESOURCE_FILE "${CMAKE_CURRENT_SOURCE_DIR}/config/update_default_resources.c")
    else ()
      MESSAGE ("Setting update resource descriptor file to \"${MBED_UPDATE_RESOURCE_FILE}\".")
    endif()

    add_definitions ("-DMBED_CLOUD_DEV_UPDATE_ID=1")
    add_definitions ("-DMBED_CLOUD_DEV_UPDATE_CERT=1")

    add_library (mbed-update-default-resources ${MBED_UPDATE_RESOURCE_FILE})

  else()
    MESSAGE ("Firmware update enabled. But not DEVELOPER mode.")
    MESSAGE ("Update resource injection assumed to happen runtime from CBOR file.")
  endif()

  if (NOT DEFINED MBED_CLOUD_CLIENT_UPDATE_STORAGE)
    MESSAGE (FATAL_ERROR "Firmware update enabled, missing update storage flag")
  endif()

  add_definitions ("-DMBED_CLOUD_CLIENT_SUPPORT_UPDATE=1")
  add_definitions ("-DMBED_CLOUD_CLIENT_UPDATE_STORAGE=${MBED_CLOUD_CLIENT_UPDATE_STORAGE}")

endif()

# mbedtls is supported
# Custom mbedtls configuration header file can be given with argument -DMBEDTLS_CONFIG
SET (TLS_LIBRARY "mbedTLS")
if (NOT DEFINED MBEDTLS_CONFIG)
  SET (MBEDTLS_CONFIG "${CMAKE_CURRENT_SOURCE_DIR}/lib/mbed-cloud-client/mbed-client-pal/Configs/mbedTLS/mbedTLSConfig_Linux.h")
  MESSAGE ("Using default client library mbedtls config: ${MBEDTLS_CONFIG}")
endif()
add_definitions ("-DMBEDTLS_CONFIG_FILE=\"${MBEDTLS_CONFIG}\"")

# Select Device Management Client configuration header
# Custom configuration header file can be given with argument -DCLOUD_CLIENT_CONFIG
if (NOT DEFINED CLOUD_CLIENT_CONFIG)
  SET (CLOUD_CLIENT_CONFIG "${CMAKE_CURRENT_SOURCE_DIR}/config/mbed_cloud_client_user_config.h")
  MESSAGE ("Using default Device Management Client config: ${CLOUD_CLIENT_CONFIG}")
endif()
add_definitions ("-DMBED_CLOUD_CLIENT_USER_CONFIG_FILE=\"${CLOUD_CLIENT_CONFIG}\"")
add_definitions ("-DMBED_CLIENT_USER_CONFIG_FILE=\"${CLOUD_CLIENT_CONFIG}\"")

# Internal eventloop thread stack size
if (NOT DEFINED NS_HAL_PAL_EVENLOOP_STACK_SIZE)
  SET (NS_HAL_PAL_EVENLOOP_STACK_SIZE 102400)
  MESSAGE ("Using default ns-hal-pal eventloop stack size: ${NS_HAL_PAL_EVENLOOP_STACK_SIZE}")
endif()
add_definitions ("-DMBED_CONF_NS_HAL_PAL_EVENT_LOOP_THREAD_STACK_SIZE=${NS_HAL_PAL_EVENLOOP_STACK_SIZE}")

if (NOT DEFINED EDGE_PRIMARY_NETWORK_INTERFACE_ID)
  SET (EDGE_PRIMARY_NETWORK_INTERFACE_ID "eth0")
  MESSAGE ("Using default network interface `eth0`")
endif()
add_definitions ("-DEDGE_PRIMARY_NETWORK_INTERFACE_ID=\"${EDGE_PRIMARY_NETWORK_INTERFACE_ID}\"")

if (NOT DEFINED EDGE_REGISTERED_ENDPOINT_LIMIT)
  SET (EDGE_REGISTERED_ENDPOINT_LIMIT 500)
  MESSAGE ("Using default endpoint number limit `500`")
endif()
add_definitions ("-DEDGE_REGISTERED_ENDPOINT_LIMIT=${EDGE_REGISTERED_ENDPOINT_LIMIT}")

MESSAGE ("Using PAL User defined configuration: ${PAL_USER_DEFINED_CONFIGURATION}")
add_definitions ("-DPAL_USER_DEFINED_CONFIGURATION=${PAL_USER_DEFINED_CONFIGURATION}")

MESSAGE("Using primary mount: ${PAL_FS_MOUNT_POINT_PRIMARY}")
add_definitions ("-DPAL_FS_MOUNT_POINT_PRIMARY=${PAL_FS_MOUNT_POINT_PRIMARY}")

MESSAGE("Using secondary mount: ${PAL_FS_MOUNT_POINT_SECONDARY}")
add_definitions ("-DPAL_FS_MOUNT_POINT_SECONDARY=${PAL_FS_MOUNT_POINT_SECONDARY}")

if (DEFINED PAL_UPDATE_FIRMWARE_DIR)
    add_definitions ("-DPAL_UPDATE_FIRMWARE_DIR=${PAL_UPDATE_FIRMWARE_DIR}")
    MESSAGE("Using firmware update directory: ${PAL_UPDATE_FIRMWARE_DIR}")
endif()

if (DEFINED TRACE_LEVEL)
  MESSAGE ("Trace level set to ${TRACE_LEVEL}")
  add_definitions ("-DMBED_CONF_MBED_TRACE_ENABLE=1")
  if (${TRACE_LEVEL} STREQUAL DEBUG)
        add_definitions ("-DMBED_TRACE_MAX_LEVEL=TRACE_LEVEL_DEBUG")
    elseif (${TRACE_LEVEL} STREQUAL INFO)
        add_definitions ("-DMBED_TRACE_MAX_LEVEL=TRACE_LEVEL_INFO")
    elseif (${TRACE_LEVEL} STREQUAL WARN)
        add_definitions ("-DMBED_TRACE_MAX_LEVEL=TRACE_LEVEL_WARN")
    elseif (${TRACE_LEVEL} STREQUAL ERROR)
        add_definitions ("-DMBED_TRACE_MAX_LEVEL=TRACE_LEVEL_ERROR")
    else ()
        MESSAGE (FATAL_ERROR "Unknown trace level '${TRACE_LEVEL}'")
    endif()
else()
    add_definitions ("-DMBED_TRACE_MAX_LEVEL=TRACE_LEVEL_ERROR")
endif()

add_definitions("-DMBED_CLOUD_CLIENT_EDGE_EXTENSION")

# Example application default configuration
SET (MBED_CONF_MBED_CLIENT_EVENT_LOOP_SIZE 40960)
SET (MBED_CONF_MBED_CLIENT_DNS_THREAD_STACK_SIZE 131072)
SET (SA_PV_PLAT_PC 1)
SET (RESOURCE_ATTRIBUTES_LIST 1)

#Following is needed for tests
FILE (GLOB LIBSERVICE_SOURCE
  "${CMAKE_CURRENT_SOURCE_DIR}/lib/mbed-cloud-client/nanostack-libservice/source/libBits/common_functions.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/lib/mbed-cloud-client/nanostack-libservice/source/libList/*.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/lib/mbed-cloud-client/nanostack-libservice/source/nsdynmemLIB/*.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/lib/mbed-cloud-client/nanostack-libservice/source/libip6string/ip6tos.c"
  )
CREATE_LIBRARY(libservice "${LIBSERVICE_SOURCE}" "")
