/* SPDX-License-Identifier: Apache-2.0 */
#include "developer_credentials.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/crypto.h>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <sddl.h>
typedef wchar_t pathchar;
#define SAME(a,b) (wcscmp((a),L##b) == 0)
#else
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
typedef char pathchar;
#define SAME(a,b) (strcmp((a),b) == 0)
#endif

static FILE *input_file(const pathchar *path)
{
#ifdef _WIN32
    return _wfopen(path,L"rb");
#else
    return fopen(path,"rb");
#endif
}
static int write_private(const pathchar *path, const unsigned char *p, size_t n)
{
#ifdef _WIN32
    PSECURITY_DESCRIPTOR sd = NULL; SECURITY_ATTRIBUTES sa; HANDLE file; DWORD written = 0;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)",SDDL_REVISION_1,&sd,NULL)) return 0;
    sa.nLength = sizeof(sa); sa.lpSecurityDescriptor = sd; sa.bInheritHandle = FALSE;
    file = CreateFileW(path,GENERIC_WRITE,0,&sa,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL);
    LocalFree(sd);
    if (file == INVALID_HANDLE_VALUE) return 0;
    if (!WriteFile(file,p,(DWORD)n,&written,NULL) || written != n || !FlushFileBuffers(file)) {
        CloseHandle(file); DeleteFileW(path); return 0;
    }
    return CloseHandle(file) != 0;
#else
    int flags = O_WRONLY | O_CREAT | O_EXCL, fd; size_t done = 0;
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
    fd = open(path,flags,0600);
    if (fd < 0) return 0;
    while (done < n) {
        ssize_t count = write(fd,p+done,n-done);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) { close(fd); unlink(path); return 0; }
        done += (size_t)count;
    }
    if (fsync(fd)) { close(fd); unlink(path); return 0; }
    return close(fd) == 0;
#endif
}
#ifdef _WIN32
int wmain(int argc, wchar_t **argv)
#else
int main(int argc, char **argv)
#endif
{
    const pathchar *input = NULL, *output = NULL;
    FILE *file = NULL; unsigned char *source = NULL, *bundle = NULL;
    size_t length = 0, bundle_length = 0; const char *error = NULL; int i, code = 1;
    if (argc == 2 && (SAME(argv[1],"--help") || SAME(argv[1],"help"))) {
        puts("edge-provision convert-developer --input <credentials.c> --output <new-bundle.cbor>\n"
             "Converts portal developer credentials without executing C or replacing any identity.\n"
             "Input filename is unrestricted. Output is a private, newly created CBOR bundle."); return 0;
    }
    if (argc != 6 || !SAME(argv[1],"convert-developer")) goto usage;
    for (i = 2; i < argc; i += 2) {
        if (SAME(argv[i],"--input") && !input) input = argv[i+1];
        else if (SAME(argv[i],"--output") && !output) output = argv[i+1];
        else goto usage;
    }
    if (!input || !output) goto usage;
    file = input_file(input);
    source = (unsigned char *)malloc(EDGE_CREDENTIAL_FILE_LIMIT + 1u);
    if (!file || !source) { error = "Could not read the developer credential file."; goto cleanup; }
    length = fread(source,1,EDGE_CREDENTIAL_FILE_LIMIT + 1u,file);
    if (ferror(file) || length > EDGE_CREDENTIAL_FILE_LIMIT) { error = "Credential file is unreadable or exceeds 1 MiB."; goto cleanup; }
    fclose(file); file = NULL;
    if (!edge_convert_developer(source,length,&bundle,&bundle_length,&error)) goto cleanup;
    if (!write_private(output,bundle,bundle_length)) { error = "Could not create a private output file. Existing files are never overwritten."; goto cleanup; }
    puts("Developer provisioning bundle created. Treat it as a private credential."); code = 0;
cleanup:
    if (error) fprintf(stderr,"edge-provision: %s\n",error);
    if (file) fclose(file);
    if (source) { OPENSSL_cleanse(source,EDGE_CREDENTIAL_FILE_LIMIT+1u); free(source); }
    if (bundle) { OPENSSL_cleanse(bundle,bundle_length); free(bundle); }
    return code;
usage:
    fputs("Usage: edge-provision convert-developer --input <credentials.c> --output <new-bundle.cbor>\n",stderr); return 2;
}
