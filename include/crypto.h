#pragma once
#include <stddef.h>
#include <stdint.h>

#include "sftp.h"

/* SHA-256 / HMAC-SHA256 */
void sha256(uint8_t out[32], const void* m, size_t n);
void hmac_sha256(uint8_t        out[32],
                 const uint8_t* key,
                 size_t         kn,
                 const uint8_t* m,
                 size_t         mn);

/* AES-128 ECB + CBC + PKCS7 */
void aes128_key_expand(uint8_t rk[176], const uint8_t key[16]);
void aes128_encrypt_block(uint8_t       out[16],
                          const uint8_t in[16],
                          const uint8_t rk[176]);
void aes128_decrypt_block(uint8_t       out[16],
                          const uint8_t in[16],
                          const uint8_t rk[176]);
int  cbc_encrypt(uint8_t*       dst,
                 const uint8_t* src,
                 size_t         n,
                 const uint8_t  iv[16],
                 const uint8_t  rk[176]);
int  cbc_decrypt(uint8_t*       dst,
                 const uint8_t* src,
                 size_t         n,
                 const uint8_t  iv[16],
                 const uint8_t  rk[176]);
int  pkcs7_pad(uint8_t** out, size_t* on, const uint8_t* in, size_t n);
int  pkcs7_unpad(uint8_t* buf, size_t* n);

/* MGF1 */
void mgf1_sha256(uint8_t* out, size_t outlen, const uint8_t* seed, size_t slen);

/* RSA core ops */
int rsa_public_op(bn_t out, const bn_t in, const rsa_pub* pk);
int rsa_private_op(bn_t out, const bn_t in, const rsa_priv* sk);

/* RSA-OAEP (SHA-256, L = "") */
int rsa_oaep_encrypt(struct bytes*  ct,
                     const rsa_pub* pk,
                     const uint8_t* msg,
                     size_t         mlen);
int rsa_oaep_decrypt(struct bytes*   pt,
                     const rsa_priv* sk,
                     const uint8_t*  ct,
                     size_t          clen);

/* RSA-PSS (SHA-256) */
int rsa_pss_sign(struct bytes*   sig,
                 const rsa_priv* sk,
                 const uint8_t*  msg,
                 size_t          mlen);
int rsa_pss_verify(const rsa_pub* pk,
                   const uint8_t* msg,
                   size_t         mlen,
                   const uint8_t* sig,
                   size_t         slen);

/* AE token (AES-CBC + HMAC-SHA256) */
typedef struct {
    uint8_t ek[16];
    uint8_t ak[32];
} aekey;

int ae_encrypt(struct bytes*  out,
               const aekey*   k,
               const uint8_t* pt,
               size_t         pn,
               uint32_t       ts_be);
int ae_decrypt(struct bytes*  out,
               const aekey*   k,
               const uint8_t* tok,
               size_t         tn,
               uint32_t       now_be);

/* AP/CP plumbing */
int ap_server_handle(int cfd);
int ap_client_handshake(int fd, rsa_pub* Ks_out);

int cp1_send_file(int fd, const rsa_pub* Ks, const char* path);
int cp2_send_key(int fd, const rsa_pub* Ks, aekey* out);
int cp2_send_file(int fd, const aekey* k, const char* path);
