// dump_ca_pub.c — extract RSA (n,e) from X.509 .crt (PEM or DER).
// Build: cc -std=c99 -Wall -Wextra -O2 dump_ca_pub.c -o dump_ca_pub
#define _POSIX_C_SOURCE 200809L
#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* --- tiny base64 --- */
static int b64v(int c) {
    if ('A' <= c && c <= 'Z')
        return c - 'A';
    if ('a' <= c && c <= 'z')
        return c - 'a' + 26;
    if ('0' <= c && c <= '9')
        return c - '0' + 52;
    if (c == '+')
        return 62;
    if (c == '/')
        return 63;
    return -1;
}
static uint8_t* b64_decode(const char* s, size_t n, size_t* outn) {
    uint8_t *out = malloc((n / 4 + 1) * 3), *p = out;
    if (!out)
        return NULL;
    int val = 0, valb = -8;
    for (size_t i = 0; i < n; i++) {
        int c = s[i];
        if (c == '=' || c == '\n' || c == '\r' || c == '\t' || c == ' ')
            continue;
        int v = b64v(c);
        if (v < 0)
            continue;
        val = (val << 6) | v;
        valb += 6;
        if (valb >= 0) {
            *p++ = (uint8_t) ((val >> valb) & 0xFF);
            valb -= 8;
        }
    }
    *outn = (size_t) (p - out);
    return out;
}

/* --- minimal DER --- */
struct der {
    const uint8_t* b;
    size_t         n;
    size_t         off;
};
static int der_tlv(struct der* d, uint8_t* tag, size_t* len, size_t* valoff) {
    if (d->off >= d->n)
        return -1;
    *tag = d->b[d->off++];
    if (d->off >= d->n)
        return -1;
    uint8_t l = d->b[d->off++];
    if ((l & 0x80) == 0) {
        *len = l;
    } else {
        int nb = l & 0x7F;
        if (nb == 0 || nb > 8 || d->off + nb > d->n)
            return -1;
        size_t L = 0;
        for (int i = 0; i < nb; i++)
            L = (L << 8) | d->b[d->off++];
        *len = L;
    }
    if (d->off + *len > d->n)
        return -1;
    *valoff = d->off;
    d->off += *len;
    return 0;
}

/* rsaEncryption OID 1.2.840.113549.1.1.1 */
static int is_oid_rsa(const uint8_t* v, size_t n) {
    static const uint8_t oid[] = {
        0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01};
    return n == sizeof(oid) && memcmp(v, oid, sizeof(oid)) == 0;
}
static void int_strip(const uint8_t** p, size_t* n) {
    while (*n > 0 && **p == 0x00) {
        (*p)++;
        (*n)--;
    }
}
static void print_limbs_any(const uint8_t* p, size_t n) {
    if (n % 4 == 0 && (n == 128 || n == 256)) { /* 1024 or 2048 */
        size_t limbs = n / 4;
        printf("{\n  ");
        for (size_t i = 0; i < limbs; i++) {
            uint32_t w =
                (uint32_t) p[4 * i] << 24 | (uint32_t) p[4 * i + 1] << 16
                | (uint32_t) p[4 * i + 2] << 8 | (uint32_t) p[4 * i + 3];
            printf("0x%08X%s", w, (i + 1 < limbs) ? ", " : "");
            if ((i + 1) % 4 == 0)
                printf("\n  ");
        }
        printf("}");
    } else {
        fprintf(stderr, "[warn] modulus is %zu bytes (not 1024/2048)\n", n);
        printf("{ ");
        for (size_t i = 0; i < n; i++) {
            printf("0x%02X%s", p[i], (i + 1 < n) ? "," : "");
            if ((i + 1) % 16 == 0)
                printf("\n  ");
        }
        printf(" }");
    }
}

int main(int argc, char** argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s cacert.crt\n", argv[0]);
        return 2;
    }

    /* Read whole file */
    FILE* f = fopen(argv[1], "rb");
    if (!f) {
        perror("open");
        return 1;
    }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    char* buf = malloc((size_t) sz + 1);
    if (!buf) {
        perror("malloc");
        return 1;
    }
    fread(buf, 1, (size_t) sz, f);
    fclose(f);
    buf[sz] = 0;

    /* Decode PEM → DER if needed */
    uint8_t* der       = NULL;
    size_t   dn        = 0;
    char*    pem_begin = strstr(buf, "-----BEGIN CERTIFICATE-----");
    if (pem_begin) {
        char* pem_end = strstr(pem_begin, "-----END CERTIFICATE-----");
        if (!pem_end || pem_end <= pem_begin) {
            fprintf(stderr, "bad PEM markers\n");
            return 1;
        }
        pem_begin += (int) strlen("-----BEGIN CERTIFICATE-----");
        der = b64_decode(pem_begin, (size_t) (pem_end - pem_begin), &dn);
        if (!der) {
            fprintf(stderr, "b64 decode failed\n");
            return 1;
        }
    } else {
        der = (uint8_t*) malloc((size_t) sz);
        if (!der) {
            perror("malloc");
            return 1;
        }
        memcpy(der, buf, (size_t) sz);
        dn = (size_t) sz;
    }
    free(buf);

    /* Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm,
     * signatureValue } */
    struct der d = {.b = der, .n = dn, .off = 0};
    uint8_t    tag;
    size_t     len, val;
    if (der_tlv(&d, &tag, &len, &val) || tag != 0x30) {
        fprintf(stderr, "not a SEQUENCE\n");
        return 1;
    }
    struct der cert = {.b = der + val, .n = len, .off = 0};

    /* FIRST CHILD = tbsCertificate (SEQUENCE) — descend */
    uint8_t ttag;
    size_t  tlen, tval;
    if (der_tlv(&cert, &ttag, &tlen, &tval) || ttag != 0x30) {
        fprintf(stderr, "no tbsCertificate\n");
        return 1;
    }
    struct der tbs = {.b = cert.b + tval, .n = tlen, .off = 0};

    /* Scan fields inside tbsCertificate to find SubjectPublicKeyInfo */
    int            found    = 0;
    const uint8_t* spki     = NULL;
    size_t         spki_len = 0;
    while (tbs.off < tbs.n) {
        size_t  elen, eval;
        uint8_t etag;
        if (der_tlv(&tbs, &etag, &elen, &eval))
            break;
        if (etag != 0x30)
            continue; /* SPKI is a SEQUENCE; many other fields are too */

        struct der seq = {.b = tbs.b + eval, .n = elen, .off = 0};

        /* SPKI: AlgorithmIdentifier (SEQUENCE) then BIT STRING */
        uint8_t atag;
        size_t  alen, aval;
        if (der_tlv(&seq, &atag, &alen, &aval))
            continue;
        if (atag != 0x30)
            continue;

        struct der alg = {.b = seq.b + aval, .n = alen, .off = 0};
        uint8_t    oid_tag;
        size_t     oid_len, oid_val;
        if (der_tlv(&alg, &oid_tag, &oid_len, &oid_val))
            continue;
        if (oid_tag != 0x06)
            continue; /* OID */
        if (!is_oid_rsa(alg.b + oid_val, oid_len))
            continue;

        /* Next must be BIT STRING subjectPublicKey */
        uint8_t bs_tag;
        size_t  bs_len, bs_val;
        if (der_tlv(&seq, &bs_tag, &bs_len, &bs_val))
            continue;
        if (bs_tag != 0x03)
            continue;

        spki     = seq.b + bs_val;
        spki_len = bs_len;
        found    = 1;
        break;
    }
    if (!found) {
        fprintf(stderr, "rsaEncryption SPKI not found\n");
        return 1;
    }
    if (spki_len < 1 || spki[0] != 0x00) {
        fprintf(stderr, "unexpected BIT STRING padding\n");
        return 1;
    }

    /* Inside BIT STRING (skip pad-count) → RSAPublicKey ::= SEQUENCE(INTEGER n,
     * INTEGER e) */
    struct der rsapk = {.b = spki + 1, .n = spki_len - 1, .off = 0};
    uint8_t    s_tag;
    size_t     s_len, s_val;
    if (der_tlv(&rsapk, &s_tag, &s_len, &s_val) || s_tag != 0x30) {
        fprintf(stderr, "bad RSAPublicKey\n");
        return 1;
    }
    struct der inner = {.b = rsapk.b + s_val, .n = s_len, .off = 0};

    /* modulus INTEGER */
    uint8_t m_tag;
    size_t  m_len, m_val;
    if (der_tlv(&inner, &m_tag, &m_len, &m_val) || m_tag != 0x02) {
        fprintf(stderr, "modulus missing\n");
        return 1;
    }
    const uint8_t* m  = inner.b + m_val;
    size_t         mn = m_len;
    int_strip(&m, &mn);

    /* exponent INTEGER */
    uint8_t e_tag;
    size_t  e_len, e_val;
    if (der_tlv(&inner, &e_tag, &e_len, &e_val) || e_tag != 0x02) {
        fprintf(stderr, "exponent missing\n");
        return 1;
    }
    const uint8_t* e  = inner.b + e_val;
    size_t         en = e_len;
    int_strip(&e, &en);

    /* Emit header */
    printf("#pragma once\n#include \"sftp.h\"\n");
    printf("/* CA modulus is %zu bytes (%zu bits). */\n", mn, mn * 8);
    printf("/* Define a CA key type matching this size in your code. */\n");
    printf("/* Example for 2048-bit: typedef struct { uint32_t n[64]; uint32_t "
           "e; } rsa_pub2048; */\n");
    printf("/* Paste into keys/ca_pub.h and use for CA verification. */\n");
    printf("/* n (big-endian 32-bit limbs): */\n");
    printf("/* ");
    print_limbs_any(m, mn);
    printf(" */\n");
    printf("/* e: ");
    uint32_t ev = 0;
    for (size_t i = 0; i < en; i++)
        ev = (ev << 8) | e[i];
    printf("%u */\n", ev);

    /* Or emit a ready struct if you want: */
    printf("/* static const rsa_pub2048 CA_PUB = { .n = ");
    print_limbs_any(m, mn);
    printf(", .e = %u }; */\n", ev);

    free((void*) der);
    return 0;
}
