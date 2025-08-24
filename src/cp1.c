#include <stdio.h>

#include "crypto.h"
#include "sftp.h"

int cp1_send_file(int fd, const rsa_pub* Ks, const char* path) {
    (void) fd;
    (void) Ks;
    (void) path;
    fprintf(stderr, "CP1: TODO RSA-OAEP file send\n");
    return -1;
}
