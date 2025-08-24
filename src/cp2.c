#include <stdio.h>

#include "crypto.h"
#include "sftp.h"

int cp2_send_key(int fd, const rsa_pub* Ks, aekey* out) {
    (void) fd;
    (void) Ks;
    (void) out;
    fprintf(stderr, "CP2: TODO RSA-OAEP wrap session key\n");
    return -1;
}

int cp2_send_file(int fd, const aekey* k, const char* path) {
    (void) fd;
    (void) k;
    (void) path;
    fprintf(stderr, "CP2: TODO AES-CBC+HMAC send\n");
    return -1;
}
