#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sftp.h"

static int write_all(int fd, const void* buf, size_t n) {
    const uint8_t* p   = (const uint8_t*) buf;
    size_t         off = 0;

    while (off < n) {
        ssize_t k = write(fd, p + off, n - off);
        if (k < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        off += (size_t) k;
    }
    return 0;
}

static int read_all(int fd, void* buf, size_t n) {
    uint8_t* p   = (uint8_t*) buf;
    size_t   off = 0;

    while (off < n) {
        ssize_t k = read(fd, p + off, n - off);
        if (k == 0) {
            return -1;
        }
        if (k < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        off += (size_t) k;
    }
    return 0;
}

int send_mode(int fd, uint32_t mode) {
    uint32_t be = htonl(mode);
    return write_all(fd, &be, 4);
}

int send_blob(int fd, const void* buf, uint64_t n) {
    uint64_t be = htobe64(n);
    if (write_all(fd, &be, 8)) {
        return -1;
    }
    return write_all(fd, buf, (size_t) n);
}

int recv_mode(int fd, uint32_t* mode) {
    uint32_t be = 0;
    if (read_all(fd, &be, 4)) {
        return -1;
    }
    *mode = ntohl(be);
    return 0;
}

int recv_blob(int fd, struct bytes* out, uint64_t max) {
    uint64_t be = 0;
    if (read_all(fd, &be, 8)) {
        return -1;
    }
    uint64_t n = be64toh(be);
    if (n > max) {
        return -1;
    }
    out->p = (uint8_t*) malloc((size_t) n);
    out->n = (size_t) n;
    if (!out->p) {
        return -1;
    }
    if (read_all(fd, out->p, out->n)) {
        free(out->p);
        out->p = NULL;
        out->n = 0;
        return -1;
    }
    return 0;
}

void bytes_free(struct bytes* b) {
    if (b && b->p) {
        free(b->p);
        b->p = NULL;
        b->n = 0;
    }
}

int urand(void* buf, size_t n) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        return -1;
    }
    int rc = read_all(fd, buf, n);
    close(fd);
    return rc;
}
