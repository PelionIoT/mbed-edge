

cmake_minimum_required(VERSION 2.8.11)

include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/mbed-cloud-client")


set(MBED_EDGE_BUILD_AUTO_MBED-CLOUD-CLIENT_CPP_FILES
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/mbed-client/source/m2mfirmware.cpp"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/mbed-client/source/m2mserver.cpp"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/source/ServiceClient.cpp"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/mbed-client/source/m2mblockmessage.cpp"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/mbed-client/source/m2mobject.cpp"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/source/ConnectorClient.cpp"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/mbed-client/source/m2mreporthandler.cpp"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/mbed-client/mbed-client-mbed-tls/source/m2mconnectionsecuritypimpl.cpp"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/mbed-client/source/m2mobjectinstance.cpp"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/mbed-client/source/m2mtlvdeserializer.cpp"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/mbed-client/mbed-client-c/source/sn_nsdl.c"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/mbed-client/source/m2mresource.cpp"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/source/UpdateClient.cpp"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/mbed-client/mbed-client-c/source/sn_grs.c"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/source/MbedCloudClient.cpp"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/mbed-client/source/m2minterfaceimpl.cpp"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/mbed-client/source/m2mstringbufferbase.cpp"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/mbed-client/mbed-client-classic/source/m2mconnectionhandler.cpp"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/mbed-client/source/m2mstring.cpp"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/mbed-client/source/m2mdevice.cpp"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/mbed-client/source/m2mcallbackstorage.cpp"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/mbed-client/source/m2minterfacefactory.cpp"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/mbed-client/source/m2mbase.cpp"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/source/SimpleM2MResource.cpp"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/mbed-client/mbed-client-classic/source/m2mtimer.cpp"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/source/CertificateParser.c"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/mbed-client/mbed-client-classic/source/m2mconnectionhandlerpimpl.cpp"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/mbed-client/source/m2msecurity.cpp"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/mbed-client/source/m2mresourceinstance.cpp"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/mbed-client/source/nsdlaccesshelper.cpp"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/mbed-client/mbed-client-mbed-tls/source/m2mconnectionsecurity.cpp"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/mbed-client/source/m2mendpoint.cpp"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/mbed-client/source/m2mnsdlinterface.cpp"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/source/CloudClientStorage.c"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/mbed-client/source/m2mresourcebase.cpp"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/mbed-client/mbed-client-classic/source/m2mtimerpimpl.cpp"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/mbed-client/source/m2mtlvserializer.cpp"
)
# force dependency on the config header for cpp files, which CMake otherwise wouldn't track:
set_property(SOURCE ${MBED_EDGE_BUILD_AUTO_MBED-CLOUD-CLIENT_CPP_FILES} PROPERTY OBJECT_DEPENDS "${CMAKE_SOURCE_DIR}/../../build/mcc-linux-x86/mbed_edge_config.h")
set(MBED_EDGE_BUILD_AUTO_MBED-CLOUD-CLIENT_HEADER_FILES
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/mbed-client/mbed-client/m2mobject.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/mbed-client/mbed-client/m2mconnectionobserver.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/mbed-client/mbed-client/m2mconfig.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/mbed-client/mbed-client/m2mconnectionsecurity.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/mbed-client/mbed-client/m2mstringbufferbase.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/mbed-client/mbed-client/m2mfirmware.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/mbed-client/mbed-client/m2mconstants.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/source/include/UpdateClient.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/mbed-cloud-client/MbedCloudClientConfig.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/mbed-client/mbed-client/m2minterfaceobserver.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/mbed-client/mbed-client-c/source/include/sn_grs.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/mbed-client/mbed-client/m2mvector.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/source/include/CertificateParser.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/mbed-client/mbed-client/m2mtimerobserver.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/mbed-client/mbed-client/m2mtimer.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/source/include/ServiceClient.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/mbed-client/source/include/nsdlaccesshelper.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/mbed-client/mbed-client/m2minterface.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/mbed-client/source/include/m2mreporthandler.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/mbed-client/mbed-client-classic/mbed-client-classic/m2mconnectionhandlerpimpl.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/mbed-client/source/include/nsdllinker.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/mbed-client/mbed-client-c/nsdl-c/sn_nsdl_lib.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/source/include/UpdateClientResources.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/mbed-client/source/include/m2minterfaceimpl.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/mbed-client/mbed-client/m2mendpoint.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/mbed-client/mbed-client/m2mblockmessage.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/mbed-client/mbed-client-c/nsdl-c/sn_client_config.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/mbed-client/mbed-client-c/nsdl-c/sn_nsdl.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/mbed-client/mbed-client/m2mstring.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/mbed-client/source/include/m2mtlvserializer.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/mbed-client/source/include/eventdata.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/mbed-client/source/include/m2mnsdlinterface.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/mbed-client/mbed-client/m2msecurity.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/source/include/CloudClientStorage.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/mbed-cloud-client/MbedCloudClient.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/mbed-client/mbed-client/m2mresourcebase.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/mbed-client/mbed-client-classic/mbed-client-classic/m2mtimerpimpl.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/mbed-client/mbed-client/m2minterfacefactory.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/mbed-client/mbed-client/m2mdevice.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/mbed-client/source/include/m2mtlvdeserializer.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/mbed-client/source/include/m2mnsdlobserver.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/source/include/ConnectorClient.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/mbed-client/mbed-client/m2mobservationhandler.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/mbed-client/mbed-client/m2mserver.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/mbed-client/mbed-client/m2mreportobserver.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/mbed-cloud-client/SimpleM2MResource.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/mbed-client/source/include/smartpointer.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/mbed-client/mbed-client/m2mobjectinstance.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/mbed-client/mbed-client/m2mconnectionhandler.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/mbed-client/mbed-client/m2mresourceinstance.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/mbed-client/mbed-client/m2mresource.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/mbed-client/mbed-client-mbed-tls/mbed-client-mbedtls/m2mconnectionsecuritypimpl.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/mbed-cloud-client/MbedCloudClientConfigCheck.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/mbed-client/source/include/m2mcallbackstorage.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/mbed-client/mbed-client/m2mstringbuffer.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/mbed-client/mbed-client/m2mbase.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/mbed-client/mbed-client/functionpointer.h"
)
# force dependency on the config header for header files, which CMake otherwise wouldn't track:
set_property(SOURCE ${MBED_EDGE_BUILD_AUTO_MBED-CLOUD-CLIENT_HEADER_FILES} PROPERTY OBJECT_DEPENDS "${CMAKE_SOURCE_DIR}/../../build/mcc-linux-x86/mbed_edge_config.h")
set(MBED_EDGE_BUILD_AUTO_MBED-CLOUD-CLIENT_C_FILES
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/mbed-client/mbed-client-c/source/sn_nsdl.c"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/mbed-client/mbed-client-c/source/sn_grs.c"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/source/CertificateParser.c"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/source/CloudClientStorage.c"
)
# force dependency on the config header for c files, which CMake otherwise wouldn't track:
set_property(SOURCE ${MBED_EDGE_BUILD_AUTO_MBED-CLOUD-CLIENT_C_FILES} PROPERTY OBJECT_DEPENDS "${CMAKE_SOURCE_DIR}/../../build/mcc-linux-x86/mbed_edge_config.h")


add_library(mbed-cloud-client
    ${MBED_EDGE_BUILD_AUTO_MBED-CLOUD-CLIENT_CPP_FILES}
    ${MBED_EDGE_BUILD_AUTO_MBED-CLOUD-CLIENT_HEADER_FILES}
    ${MBED_EDGE_BUILD_AUTO_MBED-CLOUD-CLIENT_C_FILES}
)

edge_postprocess_target(LIBRARY mbed-cloud-client)



target_link_libraries(mbed-cloud-client
    factory-configurator-client
    pal
    update-client-hub
    mbed-coap
    nanostack-randlib
    mbed-trace
    ns-hal-pal
    sal-stack-nanostack-eventloop
    mbed-client-esfs
)

