#include <stdio.h>

#include "keys/server_keys.h"

#include "crypto.h"

int main(void) {
    bn_t m = {0}, c = {0}, p = {0};
    bn_from_u32(m, 42);
    if (rsa_public_op(c, m, &S_PUB)) {
        puts("rsa_public_op failed");
        return 1;
    }
    if (rsa_private_op(p, c, &S_PRIV)) {
        puts("rsa_private_op failed");
        return 1;
    }
    puts("RSA test TODO: compare m and p.");
    return 0;
}
