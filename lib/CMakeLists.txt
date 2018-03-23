set_property(GLOBAL PROPERTY TARGET_SUPPORTS_SHARED_LIBS TRUE)

if (TARGET_GROUP STREQUAL test)
  add_subdirectory (cpputest)
endif ()

add_library (fstrm STATIC fstrm/fstrm/control.c)
add_library (jsonrpc STATIC jsonrpc/jsonrpc.c)
target_include_directories(fstrm PUBLIC fstrm)
