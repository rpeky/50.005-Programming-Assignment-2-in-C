#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "crypto.h"
#include "sftp.h"

static int dial(const char* host, const char* port) {
    struct addrinfo hints = {0}, *ai = NULL;
    int             s = -1;

    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host, port, &hints, &ai)) {
        return -1;
    }
    for (struct addrinfo* p = ai; p; p = p->ai_next) {
        s = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (s < 0) {
            continue;
        }
        if (connect(s, p->ai_addr, p->ai_addrlen) == 0) {
            freeaddrinfo(ai);
            return s;
        }
        close(s);
        s = -1;
    }
    freeaddrinfo(ai);
    return -1;
}

int main(int argc, char** argv) {
    if (argc != 4) {
        fprintf(stderr, "usage: %s <host> <port> <file>\n", argv[0]);
        return 2;
    }
    int fd = dial(argv[1], argv[2]);
    if (fd < 0) {
        perror("connect");
        return 1;
    }
    rsa_pub Ks;
    if (ap_client_handshake(fd, &Ks)) {
        fprintf(stderr, "AP failed\n");
        close(fd);
        return 1;
    }
    aekey k;
    if (cp2_send_key(fd, &Ks, &k) == 0) {
        cp2_send_file(fd, &k, argv[3]);
    }
    close(fd);
    return 0;
}
