#pragma once
#include <stddef.h>
#include <stdint.h>

/* 2048-bit limbs: LIMBS*32 = 2048. 1024-bit values are zero-extended. */
#define LIMBS 64

/* Big-endian words: a[0] is the most significant 32 bits. */
typedef uint32_t bn_t[LIMBS];

/* Core ops you will implement. */
void bn_zero(bn_t a);
void bn_copy(bn_t a, const bn_t b);
int  bn_cmp(const bn_t a, const bn_t b); /* -1,0,1 */

void bn_add(bn_t r, const bn_t a, const bn_t b); /* mod 2^2048 */
void bn_sub(bn_t r, const bn_t a, const bn_t b); /* assume a>=b */
void bn_shr1(bn_t r, const bn_t a);

void bn_mul_karatsuba(uint32_t   r[2 * LIMBS],
                      const bn_t a,
                      const bn_t b); /* 4096 bits */
void bn_mod(bn_t r, const uint32_t a[2 * LIMBS], const bn_t m);
void bn_powmod(bn_t r, const bn_t base, const bn_t exp, const bn_t mod);
void bn_gcd(bn_t g, const bn_t a, const bn_t b);
void bn_modinv(bn_t r, const bn_t a, const bn_t m);

void bn_from_u32(bn_t r, uint32_t x);
void bn_dec(bn_t a);
void bn_set_bit(bn_t a, int bit, int v); /* 0..2047 */
void bn_rand_bits(bn_t r, int bits);

int bn_is_odd(const bn_t a);
int bn_is_zero(const bn_t a);

/* Debug helpers. */
void bn_print_u32_array(const bn_t a);
