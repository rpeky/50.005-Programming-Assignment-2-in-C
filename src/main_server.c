#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "crypto.h"
#include "sftp.h"

static int listen_on(const char* port) {
    struct addrinfo hints = {0}, *ai = NULL;
    int             s = -1, yes = 1;

    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags    = AI_PASSIVE;

    if (getaddrinfo(NULL, port, &hints, &ai)) {
        return -1;
    }
    for (struct addrinfo* p = ai; p; p = p->ai_next) {
        s = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (s < 0) {
            continue;
        }
        setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
        if (bind(s, p->ai_addr, p->ai_addrlen) == 0) {
            if (listen(s, 16) == 0) {
                freeaddrinfo(ai);
                return s;
            }
        }
        close(s);
        s = -1;
    }
    freeaddrinfo(ai);
    return -1;
}

int main(int argc, char** argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <port>\n", argv[0]);
        return 2;
    }
    int s = listen_on(argv[1]);
    if (s < 0) {
        perror("listen");
        return 1;
    }
    for (;;) {
        int c = accept(s, NULL, NULL);
        if (c < 0) {
            perror("accept");
            continue;
        }
        ap_server_handle(c);
        close(c);
    }
}
