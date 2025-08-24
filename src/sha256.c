#include <stdio.h>
#include <stdlib.h>

#include "crypto.h"

static void unimpl(const char* f) {
    fprintf(stderr, "sha256: %s unimplemented\n", f);
    abort();
}

void sha256(uint8_t out[32], const void* m, size_t n) {
    (void) out;
    (void) m;
    (void) n;
    unimpl(__func__);
}

void hmac_sha256(uint8_t        out[32],
                 const uint8_t* key,
                 size_t         kn,
                 const uint8_t* msg,
                 size_t         mn) {
    (void) out;
    (void) key;
    (void) kn;
    (void) msg;
    (void) mn;
    unimpl(__func__);
}
