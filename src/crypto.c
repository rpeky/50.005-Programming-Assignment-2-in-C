#include "crypto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void unimpl(const char* f) {
    fprintf(stderr, "crypto: %s unimplemented\n", f);
    abort();
}

void mgf1_sha256(uint8_t*       out,
                 size_t         outlen,
                 const uint8_t* seed,
                 size_t         slen) {
    (void) out;
    (void) outlen;
    (void) seed;
    (void) slen;
    unimpl(__func__);
}

int rsa_public_op(bn_t out, const bn_t in, const rsa_pub* pk) {
    (void) out;
    (void) in;
    (void) pk;
    unimpl(__func__);
    return -1;
}

int rsa_private_op(bn_t out, const bn_t in, const rsa_priv* sk) {
    (void) out;
    (void) in;
    (void) sk;
    unimpl(__func__);
    return -1;
}

int rsa_oaep_encrypt(struct bytes*  ct,
                     const rsa_pub* pk,
                     const uint8_t* msg,
                     size_t         mlen) {
    (void) ct;
    (void) pk;
    (void) msg;
    (void) mlen;
    unimpl(__func__);
    return -1;
}

int rsa_oaep_decrypt(struct bytes*   pt,
                     const rsa_priv* sk,
                     const uint8_t*  ctb,
                     size_t          clen) {
    (void) pt;
    (void) sk;
    (void) ctb;
    (void) clen;
    unimpl(__func__);
    return -1;
}

int rsa_pss_sign(struct bytes*   sig,
                 const rsa_priv* sk,
                 const uint8_t*  msg,
                 size_t          mlen) {
    (void) sig;
    (void) sk;
    (void) msg;
    (void) mlen;
    unimpl(__func__);
    return -1;
}

int rsa_pss_verify(const rsa_pub* pk,
                   const uint8_t* msg,
                   size_t         mlen,
                   const uint8_t* sig,
                   size_t         slen) {
    (void) pk;
    (void) msg;
    (void) mlen;
    (void) sig;
    (void) slen;
    unimpl(__func__);
    return -1;
}

int ae_encrypt(struct bytes*  out,
               const aekey*   k,
               const uint8_t* pt,
               size_t         pn,
               uint32_t       ts_be) {
    (void) out;
    (void) k;
    (void) pt;
    (void) pn;
    (void) ts_be;
    unimpl(__func__);
    return -1;
}

int ae_decrypt(struct bytes*  out,
               const aekey*   k,
               const uint8_t* tok,
               size_t         tn,
               uint32_t       now_be) {
    (void) out;
    (void) k;
    (void) tok;
    (void) tn;
    (void) now_be;
    unimpl(__func__);
    return -1;
}
