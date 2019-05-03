# Workaround for: https://github.com/libevent/libevent/issues/482
# Applies for CMake build for libevent 2.1.8-stable
# Fixing commit: https://github.com/libevent/libevent/commit/66a4eb0c3ae3b1f22b084b2d3aeb5c872f37efbd
set(EVENT__HAVE_WAITPID_WITH_WNOWAIT_EXITCODE 1)
set(EVENT__HAVE_WAITPID_WITH_WNOWAIT_EXITCODE__TRYRUN_OUTPUT "")
set (EVENT__DISABLE_DEBUG_MODE ON CACHE BOOL "Disable libevent debug mode.")
set (EVENT__DISABLE_TESTS ON CACHE BOOL "Disable libevent tests.")
set (EVENT__DISABLE_REGRESS ON CACHE BOOL "Disable libevent regression tests.")
set (EVENT__DISABLE_SAMPLES ON CACHE BOOL "Disable libevent samples.")
set (EVENT__DISABLE_OPENSSL ON CACHE BOOL "Disable OpenSSL support from libevent.")
set (EVENT__DISABLE_BENCHMARK ON CACHE BOOL "Disable libevent bencmark executables.")

add_subdirectory (libevent)
