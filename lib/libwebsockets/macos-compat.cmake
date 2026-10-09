# Keep the pinned vendor checkout intact. Its Unix private header confuses a
# socket option with a send flag. LWS already ignores SIGPIPE on Unix; a zero
# send flag also works on the macOS 14 deployment floor.
set(lws_macos_header "${CMAKE_CURRENT_LIST_DIR}/libwebsockets/lib/plat/unix/private.h")
file(READ "${lws_macos_header}" lws_macos_contents)
set(lws_macos_old "#ifdef __APPLE__\n#define MSG_NOSIGNAL SO_NOSIGPIPE\n#endif")
string(FIND "${lws_macos_contents}" "${lws_macos_old}" lws_macos_match)
if (lws_macos_match EQUAL -1)
    message(FATAL_ERROR "Bundled libwebsockets changed: review macOS send flags.")
endif ()
string(REPLACE "${lws_macos_old}"
    "#ifdef __APPLE__\n#ifdef MSG_NOSIGNAL\n#undef MSG_NOSIGNAL\n#endif\n#define MSG_NOSIGNAL 0\n#endif"
    lws_macos_contents "${lws_macos_contents}")
set(lws_macos_overlay "${CMAKE_CURRENT_BINARY_DIR}/macos-compat")
file(MAKE_DIRECTORY "${lws_macos_overlay}/plat/unix")
file(WRITE "${lws_macos_overlay}/plat/unix/private.h.in" "${lws_macos_contents}")
configure_file("${lws_macos_overlay}/plat/unix/private.h.in"
    "${lws_macos_overlay}/plat/unix/private.h" COPYONLY)
target_include_directories(websockets BEFORE PRIVATE "${lws_macos_overlay}")
target_compile_options(websockets PRIVATE -Wno-unused-but-set-variable)
