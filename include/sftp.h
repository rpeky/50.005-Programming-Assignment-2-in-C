#pragma once
#include <stddef.h>
#include <stdint.h>

#include "bn.h"

enum {
    MODE_FILENAME = 0,
    MODE_DATA     = 1,
    MODE_CLOSE    = 2,
    MODE_AP       = 3,
    MODE_CP2      = 4
};

struct bytes {
    uint8_t* p;
    size_t   n;
};

int  send_mode(int fd, uint32_t mode);
int  send_blob(int fd, const void* buf, uint64_t n);
int  recv_mode(int fd, uint32_t* mode);
int  recv_blob(int fd, struct bytes* out, uint64_t max);
void bytes_free(struct bytes* b);

int urand(void* buf, size_t n);

/* Unified RSA types (2048-bit math). */
typedef struct {
    bn_t     n;
    uint32_t e;
} rsa_pub;

typedef struct {
    bn_t n;
    bn_t d;
} rsa_priv;

static inline size_t rsa_mod_bytes(const bn_t n) {
    size_t i = 0;
    while (i < LIMBS && n[i] == 0) {
        i++;
    }
    if (i == LIMBS) {
        return 1;
    }
    size_t   bits = (LIMBS - i) * 32u;
    uint32_t w    = n[i];
    int      lz   = __builtin_clz(w);
    bits -= (unsigned) lz;
    return (bits + 7u) / 8u;
}
