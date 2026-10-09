/* SPDX-License-Identifier: Apache-2.0 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define MBED_EDGE_ENABLE_BYOC_JSON 1
#include "edge_core_clip.h"

#define CHECK(expression) do { if (!(expression)) { \
    fprintf(stderr, "%s:%d: %s failed\n", __FILE__, __LINE__, #expression); exit(1); \
} } while (0)

int main(void)
{
    char *defaults[] = {"edge-core"};
    DocoptArgs args = docopt(1, defaults, false, NULL);
    CHECK(!strcmp(args.bind, "127.0.0.1"));
    CHECK(!strcmp(args.edge_pt_domain_socket, "/tmp/edge.sock"));
    CHECK(!strcmp(args.http_port, "8080"));
    CHECK(args.json_conf == NULL && args.cbor_conf == NULL);
    CHECK(!args.status_tcp && !strcmp(args.status_socket, "edge-status/status.sock"));
    CHECK(args.help_message != NULL && strstr(args.help_message, "Edge Core") != NULL);
    char *options[] = {"edge-core", "--bind=127.0.0.2", "--http-port", "0",
        "--edge-pt-domain-socket", "/tmp/path with spaces.sock", "--json-conf=identity.json"};
    args = docopt(7, options, false, NULL);
    CHECK(!strcmp(args.bind, "127.0.0.2"));
    CHECK(!strcmp(args.http_port, "0"));
    CHECK(!strcmp(args.edge_pt_domain_socket, "/tmp/path with spaces.sock"));
    CHECK(!strcmp(args.json_conf, "identity.json"));
    char *short_options[] = {"edge-core", "-b", "127.0.0.3", "-c", "identity.cbor", "-o8081"};
    args = docopt(6, short_options, false, NULL);
    CHECK(!strcmp(args.bind, "127.0.0.3"));
    CHECK(!strcmp(args.cbor_conf, "identity.cbor"));
    CHECK(!strcmp(args.http_port, "8081"));
    char *status_options[] = {"edge-core", "--status-socket=/private/tmp/private/status.sock", "--status-tcp"};
    args = docopt(3, status_options, false, NULL);
    CHECK(args.status_tcp && !strcmp(args.status_socket, "/private/tmp/private/status.sock"));
    puts("macOS BYOC defaults and short/long option parsing passed");
    return 0;
}
