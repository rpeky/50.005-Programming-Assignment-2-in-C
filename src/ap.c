#include <stdio.h>

#include "keys/ca_pub.h"
#include "keys/server_keys.h"

#include "crypto.h"
#include "sftp.h"

int ap_server_handle(int cfd) {
    (void) cfd;
    fprintf(stderr, "AP server: TODO implement handshake/sign/cert\n");
    return -1;
}

int ap_client_handshake(int fd, rsa_pub* Ks_out) {
    (void) fd;
    (void) Ks_out;
    fprintf(stderr, "AP client: TODO implement verify CA + server PSS\n");
    return -1;
}
