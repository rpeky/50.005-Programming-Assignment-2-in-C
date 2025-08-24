/* src/keygen.c — pure C RSA-1024 keygen → header on stdout */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bn.h"
#include "crypto.h"
#include "sftp.h"

static int mr_is_probable_prime(const bn_t n) {
    /* Miller–Rabin using bn_powmod; implement properly */
    (void) n;
    fprintf(stderr, "keygen: MR test unimplemented\n");
    return 0;
}
static void gen_prime(bn_t p) {
    for (;;) {
        bn_rand_bits(p, 512);
        /* ensure odd, set top bit */
        p[0] |= 0x80000000u;
        p[LIMBS - 1] |= 1u;
        if (mr_is_probable_prime(p))
            break;
    }
}

int main(void) {
    bn_t p, q, n, pm1, qm1, phi, e, d, g;
    bn_zero(p);
    bn_zero(q);
    bn_zero(n);
    bn_zero(pm1);
    bn_zero(qm1);
    bn_zero(phi);
    bn_zero(e);
    bn_zero(d);
    bn_zero(g);

    gen_prime(p);
    do {
        gen_prime(q);
    } while (bn_cmp(p, q) == 0);

    /* n = p*q */
    uint32_t tmp[2 * LIMBS];
    bn_mul_karatsuba(tmp, p, q);
    bn_mod(n, tmp, n); /* replace with proper reduce */

    /* φ = lcm(p-1,q-1) */
    bn_copy(pm1, p);
    bn_dec(pm1);
    bn_copy(qm1, q);
    bn_dec(qm1);
    bn_gcd(g, pm1, qm1);
    /* phi = (pm1*qm1)/g  — left as an exercise to your bn ops */

    bn_from_u32(e, 65537u);
    /* ensure gcd(e,pm1)=gcd(e,qm1)=1; else re-gen */
    bn_modinv(d, e, phi);

    printf("#pragma once\n#include \"sftp.h\"\n");
    printf("static const rsa_pub1024 S_PUB = {.n={\n");
    bn_print_u32_array(n);
    printf("}, .e=65537u};\n");
    printf("static const rsa_priv1024 S_PRIV = {.n={\n");
    bn_print_u32_array(n);
    printf("}, .d={\n");
    bn_print_u32_array(d);
    printf("}};\n");
    return 0;
}
