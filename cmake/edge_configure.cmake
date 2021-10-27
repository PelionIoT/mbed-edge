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
SET (EDGE_CLIENT_REQUEST_TIMEOUT_THRESHOLD_MS 1800000) # Thirty minute

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
  else ()
    add_definitions(-DMBED_EDGE_UNIT_TEST_BUILD)
  endif()
elseif (${BYOC_MODE})
  MESSAGE ("BYOC mode provisioning set.")
  add_definitions ("-DBYOC_MODE=1")
elseif (${FACTORY_MODE})
  MESSAGE ("Factory mode provisioning set.")
  add_definitions("-DPARSEC_TPM_SE_SUPPORT")

  if(PARSEC_TPM_SE_SUPPORT)
    option(LINK_WITH_TRUSTED_STORAGE "Explicitly link mbed TLS library to trusted_storage." ON)
    add_definitions(
        -DPSA_STORAGE_USER_CONFIG_FILE="${CMAKE_CURRENT_SOURCE_DIR}/config/psa_storage_user_config.h"
        -DMBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
        -DMBEDTLS_USE_PSA_CRYPTO
        -DMBEDTLS_PSA_CRYPTO_C
        -DMBEDTLS_PSA_CRYPTO_STORAGE_C
    )
    add_definitions(
        -DMBEDTLS_PSA_CRYPTO_SE_C
        -DMBED_CONF_MBED_CLOUD_CLIENT_SECURE_ELEMENT_SUPPORT
        -DMBED_CONF_APP_SECURE_ELEMENT_PARSEC_TPM_SUPPORT
        -DMBED_CONF_MBED_CLOUD_CLIENT_NON_PROVISIONED_SECURE_ELEMENT
    )
  endif()

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

MESSAGE("FOTA_ENABLE is ${FOTA_ENABLE}")

if (FOTA_ENABLE AND NOT FIRMWARE_UPDATE)
  MESSAGE (FATAL_ERROR "FIRMWARE_UPDATE flag should be enabled when using FOTA_ENABLE")
endif()

if (${FIRMWARE_UPDATE})
  MESSAGE ("Enabling firmware update for Edge")

  if (FOTA_ENABLE)
    execute_process ( COMMAND cp ${CMAKE_CURRENT_SOURCE_DIR}/fota/fota_app_callbacks.c ${CMAKE_CURRENT_SOURCE_DIR}/lib/mbed-cloud-client/fota/ )
    if (NOT DEFINED FOTA_SCRIPT_DIR)
      SET (FOTA_SCRIPT_DIR \"/opt/pelion\")
    endif()
    if (NOT DEFINED FOTA_INSTALL_MAIN_SCRIPT)
      SET (FOTA_INSTALL_MAIN_SCRIPT \"fota_update_activate.sh\")
    endif()
    if (NOT DEFINED BOOT_CAPSULE_UPDATE_DIR)
      SET (BOOT_CAPSULE_UPDATE_DIR \"/boot/efi/EFI/UpdateCapsule\")
    endif()
    if (NOT DEFINED BOOT_CAPSULE_UPDATE_FILENAME)
      SET (BOOT_CAPSULE_UPDATE_FILENAME \"u-boot-caps.bin\")
    endif()

    add_definitions(-DFOTA_DEFAULT_APP_IFS=1)
    add_definitions(-DTARGET_LIKE_LINUX=1)
    add_definitions(-DFOTA_SCRIPT_DIR=${FOTA_SCRIPT_DIR})
    add_definitions(-DFOTA_INSTALL_MAIN_SCRIPT=${FOTA_INSTALL_MAIN_SCRIPT})
    if (FOTA_COMBINED_IMAGE_SUPPORT) 
      add_definitions(-DMBED_CLOUD_CLIENT_FOTA_SUB_COMPONENT_SUPPORT=1)
      add_definitions(-DFOTA_CUSTOM_PLATFORM=1)
      add_definitions(-DFOTA_COMBINED_IMAGE_VENDOR_MAX_DATA_SIZE=64)
      add_definitions(-DBOOT_CAPSULE_UPDATE_DIR=${BOOT_CAPSULE_UPDATE_DIR})
      add_definitions(-DBOOT_CAPSULE_UPDATE_FILENAME=${BOOT_CAPSULE_UPDATE_FILENAME})
    endif()
  endif()

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
  if (FOTA_ENABLE)
    add_definitions(-DMBED_CLOUD_CLIENT_FOTA_ENABLE=1)
    SET (ENABLE_SUBDEVICE_FOTA ON)
    SET (MBED_CLOUD_CLIENT_FOTA_ENABLE ON)
    add_definitions(-DMBED_EDGE_SUBDEVICE_FOTA)
    add_definitions(-DFOTA_TEST_MANIFEST_BYPASS_VALIDATION=1)
    if (DEFINED SUBDEVICE_FIRMWARE_DOWNLOAD_LOCATION)
      add_definitions ("-DSUBDEVICE_FIRMWARE_DOWNLOAD_LOCATION=${SUBDEVICE_FIRMWARE_DOWNLOAD_LOCATION}")
      MESSAGE("Using firmware update directory: ${SUBDEVICE_FIRMWARE_DOWNLOAD_LOCATION}")
    endif()

  endif()
  if (NOT FOTA_ENABLE)
     MESSAGE("Update client hub selected.")
     add_definitions ("-DMBED_CLOUD_CLIENT_SUPPORT_UPDATE=1")
     add_definitions("-DPAL_DNS_API_VERSION=1")
     message("WARNING: The next release, 0.20, will deprecate the Update Client (UC) hub library. Please use the new FOTA framework library, which can be enabled by adding -DFOTA_ENABLE=ON flag.")
     set(ENABLE_UC_HUB ON)
  endif()

  add_definitions ("-DMBED_CLOUD_CLIENT_UPDATE_STORAGE=${MBED_CLOUD_CLIENT_UPDATE_STORAGE}")
endif()

if(SDA_WITH_EDGE)
  add_definitions("-DMBED_CLOUD_CLIENT_ENABLE_SDA=1")
  add_definitions("-DEDGE_ENABLE_SDA=1")
  SET (TRUST_ANCHOR "${CMAKE_CURRENT_SOURCE_DIR}/config/mbed_cloud_trust_anchor_credentials.c")
  add_library(sda-trust-anchor ${TRUST_ANCHOR})
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

if (PARSEC_TPM_SE_SUPPORT)
  SET (PAL_USER_DEFINED_CONFIGURATION "${CMAKE_CURRENT_SOURCE_DIR}/config/sotp_fs_linux.h")
  MESSAGE ("Using PAL configuration for PARSEC ${PAL_USER_DEFINED_CONFIGURATION}")
  add_definitions ("-DPAL_USER_DEFINED_CONFIGURATION=\"${PAL_USER_DEFINED_CONFIGURATION}\"")
else()
  MESSAGE ("Using PAL User defined configuration: ${PAL_USER_DEFINED_CONFIGURATION}")
  add_definitions ("-DPAL_USER_DEFINED_CONFIGURATION=${PAL_USER_DEFINED_CONFIGURATION}")
endif()

MESSAGE("Using primary mount: ${PAL_FS_MOUNT_POINT_PRIMARY}")
add_definitions ("-DPAL_FS_MOUNT_POINT_PRIMARY=${PAL_FS_MOUNT_POINT_PRIMARY}")

MESSAGE("Using secondary mount: ${PAL_FS_MOUNT_POINT_SECONDARY}")
add_definitions ("-DPAL_FS_MOUNT_POINT_SECONDARY=${PAL_FS_MOUNT_POINT_SECONDARY}")
if(PARSEC_TPM_SE_SUPPORT)
  SET(PAL_TLS_BSP_DIR "${CMAKE_CURRENT_SOURCE_DIR}/lib/mbed-cloud-client/mbed-client-pal/Configs/${TLS_LIBRARY}")

  if (${TLS_LIBRARY} MATCHES mbedTLS)
      # PAL specific configurations for mbedTLS
      add_definitions(-DMBEDTLS_CONFIG_FILE="${PAL_TLS_BSP_DIR}/mbedTLSConfig_${OS_BRAND}.h")
      message("PAL_TLS_BSP_DIR ${PAL_TLS_BSP_DIR}/mbedTLSConfig_${OS_BRAND}.h")
  endif()
endif()
if (DEFINED PAL_UPDATE_FIRMWARE_DIR)
    add_definitions ("-DPAL_UPDATE_FIRMWARE_DIR=${PAL_UPDATE_FIRMWARE_DIR}")
    MESSAGE("Using firmware update directory: ${PAL_UPDATE_FIRMWARE_DIR}")
endif()

add_definitions ("-DDISABLE_PAL_TESTS")

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
