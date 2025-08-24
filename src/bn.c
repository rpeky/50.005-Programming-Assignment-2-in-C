#include "bn.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void unimpl(const char* f) {
    fprintf(stderr, "bn: %s unimplemented\n", f);
    abort();
}

void bn_zero(bn_t a) { memset(a, 0, sizeof(bn_t)); }

void bn_copy(bn_t a, const bn_t b) { memcpy(a, b, sizeof(bn_t)); }

int bn_cmp(const bn_t a, const bn_t b) {
    for (int i = 0; i < LIMBS; i++) {
        if (a[i] != b[i]) {
            return a[i] < b[i] ? -1 : 1;
        }
    }
    return 0;
}

void bn_add(bn_t r, const bn_t a, const bn_t b) {
    (void) r;
    (void) a;
    (void) b;
    unimpl(__func__);
}

void bn_sub(bn_t r, const bn_t a, const bn_t b) {
    (void) r;
    (void) a;
    (void) b;
    unimpl(__func__);
}

void bn_shr1(bn_t r, const bn_t a) {
    (void) r;
    (void) a;
    unimpl(__func__);
}

void bn_mul_karatsuba(uint32_t r[2 * LIMBS], const bn_t a, const bn_t b) {
    (void) r;
    (void) a;
    (void) b;
    unimpl(__func__);
}

void bn_mod(bn_t r, const uint32_t a[2 * LIMBS], const bn_t m) {
    (void) r;
    (void) a;
    (void) m;
    unimpl(__func__);
}

void bn_powmod(bn_t r, const bn_t base, const bn_t exp, const bn_t mod) {
    (void) r;
    (void) base;
    (void) exp;
    (void) mod;
    unimpl(__func__);
}

void bn_gcd(bn_t g, const bn_t a, const bn_t b) {
    (void) g;
    (void) a;
    (void) b;
    unimpl(__func__);
}

void bn_modinv(bn_t r, const bn_t a, const bn_t m) {
    (void) r;
    (void) a;
    (void) m;
    unimpl(__func__);
}

void bn_from_u32(bn_t r, uint32_t x) {
    memset(r, 0, sizeof(bn_t));
    r[LIMBS - 1] = x;
}

void bn_dec(bn_t a) {
    (void) a;
    unimpl(__func__);
}

void bn_set_bit(bn_t a, int bit, int v) {
    (void) a;
    (void) bit;
    (void) v;
    unimpl(__func__);
}

void bn_rand_bits(bn_t r, int bits) {
    (void) r;
    (void) bits;
    unimpl(__func__);
}

int bn_is_odd(const bn_t a) { return (a[LIMBS - 1] & 1u) != 0; }

int bn_is_zero(const bn_t a) {
    for (int i = 0; i < LIMBS; i++) {
        if (a[i]) {
            return 0;
        }
    }
    return 1;
}

void bn_print_u32_array(const bn_t a) {
    for (int i = 0; i < LIMBS; i++) {
        printf("0x%08X%s", a[i], (i + 1 < LIMBS) ? ", " : "");
        if ((i + 1) % 4 == 0) {
            printf("\n");
        }
    }
}
