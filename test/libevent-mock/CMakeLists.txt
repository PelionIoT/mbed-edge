file (GLOB SOURCES ./*.cpp ./*.c)

add_library (libevent-mock-lib ${SOURCES})

target_include_directories (libevent-mock-lib PUBLIC ${CPPUTEST_HOME}/include)
target_include_directories (libevent-mock-lib PUBLIC ${ROOT_HOME}/test/test-lib)
