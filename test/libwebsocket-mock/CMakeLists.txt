file (GLOB SOURCES ./mock_lws.cpp)
file (GLOB MINIMAL ./mock_lws_minimal.cpp)

include_directories (. ../cpputest-custom-types)

add_library (libwebsocket-mock-lib ${SOURCES})
target_include_directories (libwebsocket-mock-lib PUBLIC ${CPPUTEST_HOME}/include)

add_library (libwebsocket-mock-minimal-lib ${MINIMAL})
target_include_directories (libwebsocket-mock-minimal-lib PUBLIC ${CPPUTEST_HOME}/include)
