#include <stdio.h>
#include <stdlib.h>

#include "crypto.h"

static void unimpl(const char* f) {
    fprintf(stderr, "aes: %s unimplemented\n", f);
    abort();
}

void aes128_key_expand(uint8_t rk[176], const uint8_t key[16]) {
    (void) rk;
    (void) key;
    unimpl(__func__);
}

void aes128_encrypt_block(uint8_t       out[16],
                          const uint8_t in[16],
                          const uint8_t rk[176]) {
    (void) out;
    (void) in;
    (void) rk;
    unimpl(__func__);
}

void aes128_decrypt_block(uint8_t       out[16],
                          const uint8_t in[16],
                          const uint8_t rk[176]) {
    (void) out;
    (void) in;
    (void) rk;
    unimpl(__func__);
}

int cbc_encrypt(uint8_t*       dst,
                const uint8_t* src,
                size_t         n,
                const uint8_t  iv[16],
                const uint8_t  rk[176]) {
    (void) dst;
    (void) src;
    (void) n;
    (void) iv;
    (void) rk;
    unimpl(__func__);
    return -1;
}

int cbc_decrypt(uint8_t*       dst,
                const uint8_t* src,
                size_t         n,
                const uint8_t  iv[16],
                const uint8_t  rk[176]) {
    (void) dst;
    (void) src;
    (void) n;
    (void) iv;
    (void) rk;
    unimpl(__func__);
    return -1;
}

int pkcs7_pad(uint8_t** out, size_t* on, const uint8_t* in, size_t n) {
    (void) out;
    (void) on;
    (void) in;
    (void) n;
    unimpl(__func__);
    return -1;
}

int pkcs7_unpad(uint8_t* buf, size_t* n) {
    (void) buf;
    (void) n;
    unimpl(__func__);
    return -1;
}
