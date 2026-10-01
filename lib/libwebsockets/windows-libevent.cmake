# Apply the Windows x64 socket type corrections to a build-directory copy of
# the bundled adapter. Its upstream source and license remain intact, and no
# additional third-party branch is needed. Revisit this when updating LWS.
set(lws_event_source "${CMAKE_CURRENT_LIST_DIR}/libwebsockets/lib/event-libs/libevent/libevent.c")
file(READ "${lws_event_source}" lws_event_windows)
if (NOT lws_event_windows MATCHES "int fd" OR
    NOT lws_event_windows MATCHES "fd = wsi->desc.filefd;")
  message(FATAL_ERROR "Bundled libwebsockets adapter changed: review the Windows socket type corrections.")
endif ()
string(REPLACE "int fd" "evutil_socket_t fd" lws_event_windows "${lws_event_windows}")
string(REPLACE "fd = wsi->desc.filefd;" "fd = (evutil_socket_t)(intptr_t)wsi->desc.filefd;"
       lws_event_windows "${lws_event_windows}")
set(lws_event_output "${CMAKE_CURRENT_BINARY_DIR}/windows-libevent.c")
file(WRITE "${lws_event_output}.in" "${lws_event_windows}")
configure_file("${lws_event_output}.in" "${lws_event_output}" COPYONLY)
get_target_property(lws_source_dir websockets SOURCE_DIR)
get_target_property(lws_sources websockets SOURCES)
set(lws_windows_sources)
foreach (lws_source IN LISTS lws_sources)
  if (lws_source MATCHES "(^|/)event-libs/libevent/libevent\\.c$")
    list(APPEND lws_windows_sources "${lws_event_output}")
  elseif (IS_ABSOLUTE "${lws_source}")
    list(APPEND lws_windows_sources "${lws_source}")
  else ()
    list(APPEND lws_windows_sources "${lws_source_dir}/${lws_source}")
  endif ()
endforeach ()
set_property(TARGET websockets PROPERTY SOURCES "${lws_windows_sources}")
