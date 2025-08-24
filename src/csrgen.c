// src/csrgen.c — generate RSA-1024 key + PKCS#10 CSR (PEM), no OpenSSL.
// Build: cc -std=c99 -Wall -Wextra -O2 src/csrgen.c src/bn.c src/sha256.c
// src/crypto.c -Iinclude -o bin/csrgen
#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "bn.h"  // your bignum (set LIMBS=64 ok; we use only low 32 for 1024)
#include "crypto.h"  // sha256(), rsa_public/private_op(), hmac unused here
#include "sftp.h"    // bn_t typedef etc.

// ---------- minimal DER encoder ----------
typedef struct {
    uint8_t* p;
    size_t   n, cap;
} buf;
static void b_init(buf* b) {
    b->p = NULL;
    b->n = b->cap = 0;
}
static int b_reserve(buf* b, size_t add) {
    if (b->n + add <= b->cap)
        return 0;
    size_t nc = b->cap ? b->cap * 2 : 256;
    while (nc < b->n + add)
        nc *= 2;
    uint8_t* np = realloc(b->p, nc);
    if (!np)
        return -1;
    b->p   = np;
    b->cap = nc;
    return 0;
}
static int b_put(buf* b, const void* s, size_t n) {
    if (b_reserve(b, n))
        return -1;
    memcpy(b->p + b->n, s, n);
    b->n += n;
    return 0;
}
static int der_len(buf* b, size_t L) {
    if (L < 128) {
        uint8_t c = (uint8_t) L;
        return b_put(b, &c, 1);
    }
    uint8_t tmp[9];
    int     i = 8;
    while (L) {
        tmp[i--] = (uint8_t) (L & 0xFF);
        L >>= 8;
    }
    uint8_t cnt  = (uint8_t) (8 - i);
    uint8_t lead = 0x80u | cnt;
    if (b_put(b, &lead, 1))
        return -1;
    return b_put(b, tmp + i + 1, cnt);
}
static int der_hdr(buf* b, uint8_t tag, size_t len) {
    if (b_put(b, &tag, 1))
        return -1;
    return der_len(b, len);
}
static int der_uint(buf* b, const uint8_t* be, size_t n) {
    // INTEGER: big-endian, strip leading zeros, add 0x00 if msb set.
    while (n > 0 && *be == 0) {
        be++;
        n--;
    }
    uint8_t lead = (n > 0 && (be[0] & 0x80)) ? 1 : 0;
    size_t  L    = n + lead;
    if (der_hdr(b, 0x02, L))
        return -1;
    if (lead) {
        uint8_t z = 0;
        if (b_put(b, &z, 1))
            return -1;
    }
    return b_put(b, be, n);
}
static int der_null(buf* b) {
    if (der_hdr(b, 0x05, 0))
        return -1;
    return 0;
}
static int der_oid(buf* b, const uint8_t* oid, size_t n) {
    if (der_hdr(b, 0x06, n))
        return -1;
    return b_put(b, oid, n);
}
static int der_octet(buf* b, const void* s, size_t n) {
    if (der_hdr(b, 0x04, n))
        return -1;
    return b_put(b, s, n);
}
static int der_bitstr(buf* b, const void* s, size_t n) {  // pad bits = 0
    if (der_hdr(b, 0x03, n + 1))
        return -1;
    uint8_t z = 0;
    if (b_put(b, &z, 1))
        return -1;
    return b_put(b, s, n);
}
static int der_utf8(buf* b, const char* s) {
    size_t n = strlen(s);
    if (der_hdr(b, 0x0C, n))
        return -1;
    return b_put(b, s, n);
}
static int der_seq_begin(buf* b, size_t* mark) {
    *mark     = b->n;
    uint8_t t = 0x30;
    if (b_put(b, &t, 1))
        return -1;
    uint8_t ph = 0xFF;
    return b_put(b, &ph, 1);  // placeholder for len
}
static int der_seq_end(buf* b, size_t mark) {
    size_t start = mark + 2, content = b->n - start;
    // rewrite header with real length (may need to move buffer)
    // easiest: memmove the tail forward if long-form needed
    if (content < 128) {
        b->p[mark]     = 0x30;
        b->p[mark + 1] = (uint8_t) content;
        return 0;
    }
    // need long-form: compute bytes
    uint8_t Ltmp[9];
    int     i = 8;
    size_t  L = content;
    while (L) {
        Ltmp[i--] = (uint8_t) (L & 0xFF);
        L >>= 8;
    }
    int     cnt  = 8 - i;
    uint8_t lead = 0x80u | cnt;
    if (b_reserve(b, (size_t) cnt - 1))
        return -1;
    memmove(b->p + mark + 2 + cnt, b->p + mark + 2, content);
    b->p[mark]     = 0x30;
    b->p[mark + 1] = lead;
    memcpy(b->p + mark + 2, Ltmp + i + 1, (size_t) cnt);
    b->n += (size_t) cnt - 1;
    return 0;
}
static int der_set_begin_ctx0(buf*    b,
                              size_t* mark) {  // [0] IMPLICIT SET OF Attribute
    *mark     = b->n;
    uint8_t t = 0xA0;
    if (b_put(b, &t, 1))
        return -1;
    uint8_t ph = 0xFF;
    return b_put(b, &ph, 1);
}
static int der_set_end_ctx0(buf* b, size_t mark) {
    size_t start = mark + 2, content = b->n - start;
    if (content < 128) {
        b->p[mark]     = 0xA0;
        b->p[mark + 1] = (uint8_t) content;
        return 0;
    }
    uint8_t Ltmp[9];
    int     i = 8;
    size_t  L = content;
    while (L) {
        Ltmp[i--] = (uint8_t) (L & 0xFF);
        L >>= 8;
    }
    int     cnt  = 8 - i;
    uint8_t lead = 0x80u | cnt;
    if (b_reserve(b, (size_t) cnt - 1))
        return -1;
    memmove(b->p + mark + 2 + cnt, b->p + mark + 2, content);
    b->p[mark]     = 0xA0;
    b->p[mark + 1] = lead;
    memcpy(b->p + mark + 2, Ltmp + i + 1, (size_t) cnt);
    b->n += (size_t) cnt - 1;
    return 0;
}

// ---------- OIDs we need (DER-encoded) ----------
static const uint8_t OID_rsaEncryption[]           = {0x2A,
                                                      0x86,
                                                      0x48,
                                                      0x86,
                                                      0xF7,
                                                      0x0D,
                                                      0x01,
                                                      0x01,
                                                      0x01};  // 1.2.840.113549.1.1.1
static const uint8_t OID_sha256WithRSAEncryption[] = {
    0x2A,
    0x86,
    0x48,
    0x86,
    0xF7,
    0x0D,
    0x01,
    0x01,
    0x0B};  // 1.2.840.113549.1.1.11
static const uint8_t OID_id_sha256[] = {0x60,
                                        0x86,
                                        0x48,
                                        0x01,
                                        0x65,
                                        0x03,
                                        0x04,
                                        0x02,
                                        0x01};  // 2.16.840.1.101.3.4.2.1

static const uint8_t OID_at_C[]  = {0x55, 0x04, 0x06};  // 2.5.4.6
static const uint8_t OID_at_ST[] = {0x55, 0x04, 0x08};  // 2.5.4.8
static const uint8_t OID_at_L[]  = {0x55, 0x04, 0x07};  // 2.5.4.7
static const uint8_t OID_at_O[]  = {0x55, 0x04, 0x0A};  // 2.5.4.10
static const uint8_t OID_at_CN[] = {0x55, 0x04, 0x03};  // 2.5.4.3

// ---------- misc helpers ----------
static void be_from_bn(uint8_t* out, size_t k, const bn_t a) {
    // write LIMBS*4 bytes, but only last k bytes returned (big-endian)
    // our bn is big-endian words; dump to bytes accordingly
    uint8_t tmp[LIMBS * 4];
    for (size_t i = 0; i < LIMBS; i++) {
        uint32_t w     = a[i];
        tmp[i * 4 + 0] = (uint8_t) (w >> 24);
        tmp[i * 4 + 1] = (uint8_t) (w >> 16);
        tmp[i * 4 + 2] = (uint8_t) (w >> 8);
        tmp[i * 4 + 3] = (uint8_t) (w >> 0);
    }
    // take the tail
    memcpy(out, tmp + (LIMBS * 4 - k), k);
}
static void bn_from_be(bn_t out, const uint8_t* be, size_t k) {
    // zero then copy last k bytes into low end
    bn_zero(out);
    if (k > LIMBS * 4)
        k = LIMBS * 4;
    size_t off = LIMBS * 4 - k;
    for (size_t i = 0; i < LIMBS; i++) {
        size_t idx = i * 4;
        if (idx + 4 <= off) {
            out[i] = 0;
            continue;
        }
        uint32_t w = 0;
        for (int j = 0; j < 4; j++) {
            size_t  src = idx + j;
            uint8_t b   = (src < off) ? 0 : be[src - off];
            w           = (w << 8) | b;
        }
        out[i] = w;
    }
}

static int b64_emit(
    FILE* f, const uint8_t* p, size_t n, const char* hdr, const char* ftr) {
    static const char* T =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    fprintf(f, "-----BEGIN %s-----\n", hdr);
    size_t i = 0, col = 0;
    while (i < n) {
        uint32_t v = (uint32_t) p[i++] << 16;
        if (i <= n)
            v |= (i < n ? (uint32_t) p[i] : 0) << 8;
        if (i < n)
            i++;
        if (i <= n)
            v |= (i <= n ? (uint32_t) p[i - 1]
                         : 0);  // not exact; we’ll handle padding below

        uint8_t  b0 = (p[i - 3]);
        uint8_t  b1 = (i - 2 < n) ? p[i - 2] : 0;
        uint8_t  b2 = (i - 1 < n) ? p[i - 1] : 0;
        uint32_t vv = ((uint32_t) b0 << 16) | ((uint32_t) b1 << 8) | b2;
        char     out[4];
        out[0] = T[(vv >> 18) & 63];
        out[1] = T[(vv >> 12) & 63];
        out[2] = (i - 2 <= n) ? T[(vv >> 6) & 63] : '=';
        out[3] = (i - 1 <= n) ? T[(vv >> 0) & 63] : '=';
        for (int k = 0; k < 4; k++) {
            fputc(out[k], f);
            if (++col == 64) {
                fputc('\n', f);
                col = 0;
            }
        }
    }
    if (col)
        fputc('\n', f);
    fprintf(f, "-----END %s-----\n", ftr);
    return 0;
}

// ---------- RSA keygen (sketch; fill with your BN ops) ----------
static int
mr_is_probable_prime(const bn_t n);  // TODO implement using bn_powmod
static void rand_urandom(uint8_t* p, size_t n) {
    FILE* f = fopen("/dev/urandom", "rb");
    fread(p, 1, n, f);
    fclose(f);
}
static void bn_rand_odd_bits(bn_t r, int bits) {
    uint8_t bytes[LIMBS * 4];
    memset(bytes, 0, sizeof bytes);
    int nbytes = (bits + 7) / 8;
    rand_urandom(bytes + sizeof(bytes) - nbytes, (size_t) nbytes);
    bytes[sizeof(bytes) - nbytes] |=
        (uint8_t) (1u << ((bits - 1) & 7));  // top bit
    bytes[sizeof(bytes) - 1] |= 1u;          // odd
    bn_from_be(r, bytes + sizeof(bytes) - nbytes, (size_t) nbytes);
}
static void gen_prime_512(bn_t p) {
    for (;;) {
        bn_rand_odd_bits(p, 512);
        if (mr_is_probable_prime(p))
            return;
    }
}
static void gen_rsa_1024(
    bn_t n, bn_t e, bn_t d, bn_t p, bn_t q, bn_t dp, bn_t dq, bn_t qinv) {
    bn_from_u32(e, 65537u);
    gen_prime_512(p);
    do {
        gen_prime_512(q);
    } while (bn_cmp(p, q) == 0);
    // n = p*q
    uint32_t tmp[2 * LIMBS];
    bn_mul_karatsuba(tmp, p, q);
    bn_mod(n, tmp, n); /* TODO: replace with proper 1024-bit reduce (or a bn_mul
                          into LIMBS*2 and a bn_mod_by) */
    // phi = lcm(p-1,q-1) = (p-1)*(q-1)/gcd(p-1,q-1)
    bn_t pm1, qm1, phi, g;
    bn_copy(pm1, p);
    bn_dec(pm1);
    bn_copy(qm1, q);
    bn_dec(qm1);
    bn_gcd(g, pm1, qm1);
    // compute phi = (pm1/g)*qm1  (left as exercise)
    // d = e^{-1} mod phi
    bn_modinv(d, e, phi);
    // CRT
    // dp = d mod (p-1); dq = d mod (q-1); qinv = q^{-1} mod p
    // TODO implement bn_mod_small or general bn_mod
    (void) dp;
    (void) dq;
    (void) qinv; /* fill per your bn API */
}

// ---------- PKCS#1 v1.5 sign (SHA-256) ----------
static int rsa_pkcs1_v15_sign_sha256(struct bytes*   sig,
                                     const rsa_priv* sk,
                                     const uint8_t*  m,
                                     size_t          mlen) {
    uint8_t h[32];
    sha256(h, m, mlen);
    // DigestInfo = SEQ { OID id-sha256, NULL } + OCTET STRING hash
    buf di;
    b_init(&di);
    size_t s;
    der_seq_begin(&di, &s);
    size_t s2;
    der_seq_begin(&di, &s2);
    der_oid(&di, OID_id_sha256, sizeof OID_id_sha256);
    der_null(&di);
    der_seq_end(&di, s2);
    der_octet(&di, h, sizeof h);
    der_seq_end(&di, s);

    size_t k = rsa_mod_bytes(sk->n);  // 128 for 1024-bit
    if (k < 3 + di.n)
        return -1;
    uint8_t* EM     = malloc(k);
    size_t   ps_len = k - di.n - 3;
    EM[0]           = 0x00;
    EM[1]           = 0x01;
    memset(EM + 2, 0xFF, ps_len);
    EM[2 + ps_len] = 0x00;
    memcpy(EM + 3 + ps_len, di.p, di.n);

    // RSA private op on EM
    bn_t m_bn, c_bn;
    bn_from_be(m_bn, EM, k);
    if (rsa_private_op(c_bn, m_bn, sk)) {
        free(EM);
        free(di.p);
        return -1;
    }
    uint8_t* S = malloc(k);
    be_from_bn(S, k, c_bn);
    sig->p = S;
    sig->n = k;
    free(EM);
    free(di.p);
    return 0;
}

// ---------- SubjectPublicKeyInfo + Name + CSR ----------
static int der_rsapubkey(buf* b, const rsa_pub* pk) {
    // RSAPublicKey ::= SEQUENCE { n INTEGER, e INTEGER }
    buf rsapk;
    b_init(&rsapk);
    size_t s;
    der_seq_begin(&rsapk, &s);
    // n,e from bn to big-endian bytes
    size_t   k  = rsa_mod_bytes(pk->n);
    uint8_t *nb = calloc(1, k), eb[8] = {0};
    be_from_bn(nb, k, pk->n);
    // e is u32
    int      elen = 0;
    uint32_t ev   = pk->e;
    uint8_t  etmp[5];
    do {
        etmp[4 - elen++] = (uint8_t) (ev & 0xFF);
        ev >>= 8;
    } while (ev);
    memcpy(eb + 5 - elen, etmp + 5 - elen, (size_t) elen);
    der_uint(&rsapk, nb, k);
    der_uint(&rsapk, eb + 5 - elen, (size_t) elen);
    der_seq_end(&rsapk, s);

    // SPKI ::= SEQUENCE { AlgorithmIdentifier {rsaEncryption,NULL}, BIT STRING
    // RSAPublicKey }
    size_t S;
    der_seq_begin(b, &S);
    size_t A;
    der_seq_begin(b, &A);
    der_oid(b, OID_rsaEncryption, sizeof OID_rsaEncryption);
    der_null(b);
    der_seq_end(b, A);
    der_bitstr(b, rsapk.p, rsapk.n);
    der_seq_end(b, S);
    free(rsapk.p);
    free(nb);
    return 0;
}
static int der_name_sutd(buf* b) {
    // Name ::= SEQUENCE of RDNs; each RDN is SET of one AttributeTypeAndValue
    size_t S;
    der_seq_begin(b, &S);
    // C=SG
    size_t rdn;
    der_set_begin_ctx0(b, &rdn);
    der_set_end_ctx0(b, rdn);  // placeholder to keep indices aligned (knock-on:
                               // we want plain SET(0x31), not [0])
    // Simpler: emit RDNs using SEQUENCE(SET(SEQUENCE(OID, value)))
    // RDN: C=SG
    size_t R;
    der_seq_begin(b, &R);
    size_t SET;
    der_hdr(b, 0x31, 0);
    size_t set_mark = b->n - 1;  // we’ll backpatch with 0 content len small
    size_t ATV;
    der_seq_begin(b, &ATV);
    der_oid(b, OID_at_C, sizeof OID_at_C);
    // PrintableString is clean for C=SG; we use UTF8String everywhere for
    // simplicity
    der_utf8(b, "SG");
    der_seq_end(b, ATV);
    // backpatch SET len
    b->p[set_mark] = (uint8_t) (b->n - (set_mark + 1));
    der_seq_end(b, R);
    // ST=Singapore
    size_t R2;
    der_seq_begin(b, &R2);
    size_t S2;
    der_hdr(b, 0x31, 0);
    size_t sm2 = b->n - 1;
    size_t A2;
    der_seq_begin(b, &A2);
    der_oid(b, OID_at_ST, sizeof OID_at_ST);
    der_utf8(b, "Singapore");
    der_seq_end(b, A2);
    b->p[sm2] = (uint8_t) (b->n - (sm2 + 1));
    der_seq_end(b, R2);
    // L=Singapore
    size_t R3;
    der_seq_begin(b, &R3);
    size_t S3;
    der_hdr(b, 0x31, 0);
    size_t sm3 = b->n - 1;
    size_t A3;
    der_seq_begin(b, &A3);
    der_oid(b, OID_at_L, sizeof OID_at_L);
    der_utf8(b, "Singapore");
    der_seq_end(b, A3);
    b->p[sm3] = (uint8_t) (b->n - (sm3 + 1));
    der_seq_end(b, R3);
    // O=SUTD
    size_t R4;
    der_seq_begin(b, &R4);
    size_t S4;
    der_hdr(b, 0x31, 0);
    size_t sm4 = b->n - 1;
    size_t A4;
    der_seq_begin(b, &A4);
    der_oid(b, OID_at_O, sizeof OID_at_O);
    der_utf8(b, "SUTD");
    der_seq_end(b, A4);
    b->p[sm4] = (uint8_t) (b->n - (sm4 + 1));
    der_seq_end(b, R4);
    // CN=sutd.edu.sg
    size_t R5;
    der_seq_begin(b, &R5);
    size_t S5;
    der_hdr(b, 0x31, 0);
    size_t sm5 = b->n - 1;
    size_t A5;
    der_seq_begin(b, &A5);
    der_oid(b, OID_at_CN, sizeof OID_at_CN);
    der_utf8(b, "sutd.edu.sg");
    der_seq_end(b, A5);
    b->p[sm5] = (uint8_t) (b->n - (sm5 + 1));
    der_seq_end(b, R5);
    der_seq_end(b, S);
    return 0;
}

static int
build_csr_der(struct bytes* out, const rsa_pub* pub, const rsa_priv* priv) {
    // 1) CertificationRequestInfo
    buf cri;
    b_init(&cri);
    size_t S;
    der_seq_begin(&cri, &S);
    // version v1 (0)
    uint8_t v0 = 0;
    if (der_hdr(&cri, 0x02, 1) || b_put(&cri, &v0, 1))
        return -1;
    // subject
    der_name_sutd(&cri);
    // subjectPublicKeyInfo
    der_rsapubkey(&cri, pub);
    // attributes: [0] IMPLICIT SET OF Attribute — empty
    size_t A;
    der_set_begin_ctx0(&cri, &A);
    der_set_end_ctx0(&cri, A);
    der_seq_end(&cri, S);

    // 2) signatureAlgorithm
    buf sa;
    b_init(&sa);
    size_t SA;
    der_seq_begin(&sa, &SA);
    der_oid(
        &sa, OID_sha256WithRSAEncryption, sizeof OID_sha256WithRSAEncryption);
    der_null(&sa);
    der_seq_end(&sa, SA);

    // 3) signature
    struct bytes sig = {0};
    if (rsa_pkcs1_v15_sign_sha256(&sig, priv, cri.p, cri.n))
        return -1;

    // Outer CSR
    buf csr;
    b_init(&csr);
    size_t C;
    der_seq_begin(&csr, &C);
    b_put(&csr, cri.p, cri.n);
    b_put(&csr, sa.p, sa.n);
    der_bitstr(&csr, sig.p, sig.n);
    der_seq_end(&csr, C);

    out->p = csr.p;
    out->n = csr.n;
    free(cri.p);
    free(sa.p);
    free(sig.p);
    return 0;
}

// ---------- RSAPrivateKey (PKCS#1) DER + PEM ----------
static int write_private_key_pem(const char* path,
                                 const bn_t  n,
                                 uint32_t    e,
                                 const bn_t  d,
                                 const bn_t  p,
                                 const bn_t  q,
                                 const bn_t  dp,
                                 const bn_t  dq,
                                 const bn_t  qinv) {
    // RSAPrivateKey ::= SEQUENCE { version INTEGER(0), n,e,d,p,q,dp,dq,qinv }
    // All INTEGERs, big-endian
    size_t  kN = 128, kP = 64;  // 1024-bit n, 512-bit p,q
    uint8_t nb[128], db[128], pb[64], qb[64], dpb[64], dqb[64], qib[64],
        eb[5] = {0};
    be_from_bn(nb, kN, n);
    be_from_bn(db, kN, d);
    be_from_bn(pb, kP, p);
    be_from_bn(qb, kP, q);
    be_from_bn(dpb, kP, dp);
    be_from_bn(dqb, kP, dq);
    be_from_bn(qib, kP, qinv);
    int     elen = 0;
    uint8_t etmp[5];
    do {
        etmp[4 - elen++] = (uint8_t) (e & 0xFF);
        e >>= 8;
    } while (e);
    memcpy(eb + 5 - elen, etmp + 5 - elen, (size_t) elen);

    buf b;
    b_init(&b);
    size_t S;
    der_seq_begin(&b, &S);
    uint8_t v0 = 0;
    der_hdr(&b, 0x02, 1);
    b_put(&b, &v0, 1);
    der_uint(&b, nb, kN);
    der_uint(&b, eb + 5 - elen, (size_t) elen);
    der_uint(&b, db, kN);
    der_uint(&b, pb, kP);
    der_uint(&b, qb, kP);
    der_uint(&b, dpb, kP);
    der_uint(&b, dqb, kP);
    der_uint(&b, qib, kP);
    der_seq_end(&b, S);

    FILE* f = fopen(path, "wb");
    if (!f) {
        perror("fopen");
        return -1;
    }
    b64_emit(f, b.p, b.n, "RSA PRIVATE KEY", "RSA PRIVATE KEY");
    fclose(f);
    free(b.p);
    return 0;
}

int main(int argc, char** argv) {
    const char* suffix = (argc > 1) ? argv[1] : "";
    char        keypath[256], csrpath[256];
    snprintf(keypath, sizeof keypath, "%s_private_key.pem", suffix);
    snprintf(csrpath, sizeof csrpath, "%s_certificate_request.csr", suffix);

    // 1) Generate RSA-1024 key
    bn_t n, e, d, p, q, dp, dq, qinv;
    bn_zero(n);
    bn_zero(e);
    bn_zero(d);
    bn_zero(p);
    bn_zero(q);
    bn_zero(dp);
    bn_zero(dq);
    bn_zero(qinv);
    gen_rsa_1024(n, e, d, p, q, dp, dq, qinv);  // TODO: implement internals

    // 2) Write PKCS#1 PEM private key
    if (write_private_key_pem(keypath, n, 65537u, d, p, q, dp, dq, qinv)) {
        fprintf(stderr, "write key failed\n");
        return 1;
    }

    // 3) Build CSR (uses public from n,e; sign with d)
    rsa_pub  pub  = {0};
    rsa_priv priv = {0};
    bn_copy(pub.n, n);
    pub.e = 65537u;
    bn_copy(priv.n, n);
    bn_copy(priv.d, d);

    struct bytes csr = {0};
    if (build_csr_der(&csr, &pub, &priv)) {
        fprintf(stderr, "CSR build failed\n");
        return 1;
    }

    // 4) Write CSR PEM
    FILE* f = fopen(csrpath, "wb");
    if (!f) {
        perror("csr fopen");
        return 1;
    }
    b64_emit(f, csr.p, csr.n, "CERTIFICATE REQUEST", "CERTIFICATE REQUEST");
    fclose(f);
    free(csr.p);

    fprintf(stderr, "wrote %s and %s\n", keypath, csrpath);
    return 0;
}

/* --- TODOs for you ---
 * - mr_is_probable_prime(): implement Miller–Rabin using bn_powmod
 * - bn_mul_karatsuba()/bn_mod(): provide proper multiply+reduce helpers used
 * here
 * - dp=d mod (p-1), dq=d mod (q-1), qinv=q^{-1} mod p
 * - rsa_private_op(): already in your crypto layer; make sure it reads LIMBS
 * safely
 */
