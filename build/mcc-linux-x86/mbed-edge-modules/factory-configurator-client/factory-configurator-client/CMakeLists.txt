

cmake_minimum_required(VERSION 2.8.11)

include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/factory-configurator-client")


set(MBED_EDGE_BUILD_AUTO_FACTORY-CONFIGURATOR-CLIENT_CPP_FILES
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/fcc-bundle-handler/source/fcc_bundle_certificate_utils.c"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/utils/source/fcc_stats.c"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/fcc-bundle-handler/source/fcc_bundle_key_utils.c"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/utils/source/pv_error_handling.c"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/factory-configurator-client/source/fcc_utils.c"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/fcc-bundle-handler/source/fcc_bundle_certificate_chain_utils.c"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/factory-configurator-client/source/factory_configurator_client.c"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/crypto-service/source/cs_der_certs.c"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/factory-configurator-client/source/fcc_sotp.c"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/fcc-bundle-handler/source/fcc_bundle_handler.c"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/fcc-output-info-handler/source/fcc_output_info_handler.c"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/crypto-service/source/cs_der_keys.c"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/fcc-bundle-handler/source/fcc_bundle_common_utils.c"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/crypto-service/source/cs_hash.c"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/factory-configurator-client/source/fcc_dev_flow.c"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/ftcd-comm-socket/source/ftcd_comm_socket.cpp"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/utils/source/general_utils.c"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/crypto-service/source/cs_utils.c"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/storage/source/storage.c"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/key-config-manager/source/key_config_manager.c"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/utils/source/fcc_time_profiling.c"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/utils/source/common_utils.c"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/fcc-bundle-handler/source/fcc_bundle_config_params_utils.c"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/factory-configurator-client/source/fcc_verification.c"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/ftcd-comm-base/source/ftcd_comm_base.cpp"
)
# force dependency on the config header for cpp files, which CMake otherwise wouldn't track:
set_property(SOURCE ${MBED_EDGE_BUILD_AUTO_FACTORY-CONFIGURATOR-CLIENT_CPP_FILES} PROPERTY OBJECT_DEPENDS "${CMAKE_SOURCE_DIR}/../../build/mcc-linux-x86/mbed_edge_config.h")
set(MBED_EDGE_BUILD_AUTO_FACTORY-CONFIGURATOR-CLIENT_HEADER_FILES
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/crypto-service/crypto-service/cs_der_certs.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/factory-configurator-client/source/include/fcc_utils.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/factory-configurator-client/source/include/fcc_verification.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/utils/utils/pv_endian.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/fcc-bundle-handler/fcc-bundle-handler/fcc_bundle_handler.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/logger/logger/pv_log.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/factory-configurator-client/factory-configurator-client/fcc_defs.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/storage/storage/storage.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/crypto-service/crypto-service/cs_der_keys.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/fcc-bundle-handler/source/include/fcc_bundle_utils.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/factory-configurator-client/source/include/fcc_sotp.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/utils/utils/fcc_time_profiling.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/key-config-manager/key-config-manager/kcm_defs.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/utils/utils/common_utils.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/ftcd-comm-base/ftcd-comm-base/ftcd_comm_base.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/crypto-service/crypto-service/cs_hash.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/utils/utils/pv_macros.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/ftcd-comm-socket/ftcd-comm-socket/ftcd_comm_socket.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/utils/utils/pv_error_handling.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/utils/utils/fcc_malloc.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/fcc-output-info-handler/fcc-output-info-handler/fcc_output_info_handler.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/factory-configurator-client/factory-configurator-client/fcc_status.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/fcc-output-info-handler/fcc-output-info-handler/fcc_output_info_handler_defines.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/key-config-manager/source/include/kcm_internal.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/utils/utils/fcc_stats.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/key-config-manager/key-config-manager/key_config_manager.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/key-config-manager/key-config-manager/kcm_status.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/factory-configurator-client/factory-configurator-client/factory_configurator_client.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/crypto-service/source/include/cs_utils.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/utils/utils/general_utils.h"
)
# force dependency on the config header for header files, which CMake otherwise wouldn't track:
set_property(SOURCE ${MBED_EDGE_BUILD_AUTO_FACTORY-CONFIGURATOR-CLIENT_HEADER_FILES} PROPERTY OBJECT_DEPENDS "${CMAKE_SOURCE_DIR}/../../build/mcc-linux-x86/mbed_edge_config.h")
set(MBED_EDGE_BUILD_AUTO_FACTORY-CONFIGURATOR-CLIENT_C_FILES
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/fcc-bundle-handler/source/fcc_bundle_certificate_utils.c"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/utils/source/fcc_stats.c"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/fcc-bundle-handler/source/fcc_bundle_key_utils.c"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/utils/source/pv_error_handling.c"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/factory-configurator-client/source/fcc_utils.c"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/fcc-bundle-handler/source/fcc_bundle_certificate_chain_utils.c"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/factory-configurator-client/source/factory_configurator_client.c"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/crypto-service/source/cs_der_certs.c"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/factory-configurator-client/source/fcc_sotp.c"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/fcc-bundle-handler/source/fcc_bundle_handler.c"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/fcc-output-info-handler/source/fcc_output_info_handler.c"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/crypto-service/source/cs_der_keys.c"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/fcc-bundle-handler/source/fcc_bundle_common_utils.c"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/crypto-service/source/cs_hash.c"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/factory-configurator-client/source/fcc_dev_flow.c"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/utils/source/general_utils.c"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/crypto-service/source/cs_utils.c"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/storage/source/storage.c"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/key-config-manager/source/key_config_manager.c"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/utils/source/fcc_time_profiling.c"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/utils/source/common_utils.c"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/fcc-bundle-handler/source/fcc_bundle_config_params_utils.c"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/factory-configurator-client/source/fcc_verification.c"
)
# force dependency on the config header for c files, which CMake otherwise wouldn't track:
set_property(SOURCE ${MBED_EDGE_BUILD_AUTO_FACTORY-CONFIGURATOR-CLIENT_C_FILES} PROPERTY OBJECT_DEPENDS "${CMAKE_SOURCE_DIR}/../../build/mcc-linux-x86/mbed_edge_config.h")


add_library(factory-configurator-client
    ${MBED_EDGE_BUILD_AUTO_FACTORY-CONFIGURATOR-CLIENT_CPP_FILES}
    ${MBED_EDGE_BUILD_AUTO_FACTORY-CONFIGURATOR-CLIENT_HEADER_FILES}
    ${MBED_EDGE_BUILD_AUTO_FACTORY-CONFIGURATOR-CLIENT_C_FILES}
)

edge_postprocess_target(LIBRARY factory-configurator-client)



target_link_libraries(factory-configurator-client
    secsrv-cbor
    mbed-client-esfs
)

