# Preserve the pinned dependency and license in a build-directory copy.
# These incoming HTTP limits apply only to the native macOS build.
set(edge_http_source "${CMAKE_CURRENT_LIST_DIR}/libevent/http.c")
file(READ "${edge_http_source}" edge_http_contents)
set(edge_http_name "\tint ni_result;\n\n#ifdef EVENT__HAVE_GETNAMEINFO")
set(edge_http_accept "static void\nevhttp_get_request(struct evhttp *http, evutil_socket_t fd,\n    struct sockaddr *sa, ev_socklen_t salen)\n{\n\tstruct evhttp_connection *evcon;")
set(edge_http_link "\tTAILQ_INSERT_TAIL(&http->connections, evcon, next);\n\n\tif (evhttp_associate_new_request_with_connection(evcon) == -1)")
foreach (edge_http_fragment edge_http_name edge_http_accept edge_http_link)
    string(FIND "${edge_http_contents}" "${${edge_http_fragment}}" edge_http_match)
    if (edge_http_match EQUAL -1)
        message(FATAL_ERROR "Bundled libevent changed: review macOS HTTP compatibility and limits.")
    endif ()
endforeach ()
string(REPLACE "${edge_http_name}" [=[
	int ni_result;

#ifdef EVENT__HAVE_STRUCT_SOCKADDR_UN
	if (sa->sa_family == AF_UNIX) {
		*phost = mm_strdup("localhost");
		*pport = mm_strdup("0");
		return;
	}
#endif

#ifdef EVENT__HAVE_GETNAMEINFO]=] edge_http_contents "${edge_http_contents}")
set(edge_http_deadline [=[
/* A fixed deadline also bounds clients that drip incomplete HTTP headers. */
struct edge_http_deadline {
	struct event *event;
	struct evhttp_connection *connection;
};

static void edge_http_closed(struct evhttp_connection *connection, void *argument)
{
	struct edge_http_deadline *deadline = argument;
	evhttp_connection_set_closecb(connection, NULL, NULL);
	event_free(deadline->event);
	mm_free(deadline);
}

static void edge_http_expired(evutil_socket_t fd, short events, void *argument)
{
	struct edge_http_deadline *deadline = argument;
	(void)fd;
	(void)events;
	evhttp_connection_free(deadline->connection);
}

static int edge_http_limit_connection(struct evhttp_connection *connection)
{
	const struct timeval timeout = {5, 0};
	struct edge_http_deadline *deadline = mm_calloc(1, sizeof(*deadline));
	if (!deadline) return -1;
	deadline->connection = connection;
	deadline->event = evtimer_new(connection->base, edge_http_expired, deadline);
	if (!deadline->event || evtimer_add(deadline->event, &timeout) != 0) {
		if (deadline->event) event_free(deadline->event);
		mm_free(deadline);
		return -1;
	}
	evhttp_connection_set_closecb(connection, edge_http_closed, deadline);
	return 0;
}

]=])
set(edge_http_admit [=[
	int no_sigpipe = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &no_sigpipe, sizeof(no_sigpipe)) != 0) {
		evutil_closesocket(fd);
		return;
	}
	struct evhttp_connection *existing;
	unsigned count = 0;
	TAILQ_FOREACH(existing, &http->connections, next) ++count;
	if (count >= 8) {
		evutil_closesocket(fd);
		return;
	}
]=])
string(REPLACE "${edge_http_accept}" "${edge_http_deadline}${edge_http_accept}\n${edge_http_admit}"
    edge_http_contents "${edge_http_contents}")
string(REPLACE "${edge_http_link}"
    "\tTAILQ_INSERT_TAIL(&http->connections, evcon, next);\n\n\tif (edge_http_limit_connection(evcon) != 0) {\n\t\tevhttp_connection_free(evcon);\n\t\treturn;\n\t}\n\n\tif (evhttp_associate_new_request_with_connection(evcon) == -1)"
    edge_http_contents "${edge_http_contents}")
set(edge_http_output "${CMAKE_CURRENT_BINARY_DIR}/macos-http.c")
file(WRITE "${edge_http_output}.in" "${edge_http_contents}")
configure_file("${edge_http_output}.in" "${edge_http_output}" COPYONLY)
foreach (edge_event_target event_static event_shared event_extra_static event_extra_shared)
    if (TARGET ${edge_event_target})
        get_target_property(edge_event_source_dir ${edge_event_target} SOURCE_DIR)
        get_target_property(edge_event_sources ${edge_event_target} SOURCES)
        set(edge_event_macos_sources)
        foreach (edge_event_source IN LISTS edge_event_sources)
            if (edge_event_source MATCHES "(^|/)http\\.c$")
                list(APPEND edge_event_macos_sources "${edge_http_output}")
            elseif (IS_ABSOLUTE "${edge_event_source}")
                list(APPEND edge_event_macos_sources "${edge_event_source}")
            else ()
                list(APPEND edge_event_macos_sources "${edge_event_source_dir}/${edge_event_source}")
            endif ()
        endforeach ()
        set_property(TARGET ${edge_event_target} PROPERTY SOURCES "${edge_event_macos_sources}")
        target_include_directories(${edge_event_target} PRIVATE "${edge_event_source_dir}")
    endif ()
endforeach ()
