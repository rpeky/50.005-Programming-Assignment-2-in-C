#include <stdio.h>

#include "bn.h"

int main(void) {
    bn_t a = {0}, b = {0}, c = {0};
    bn_from_u32(a, 1);
    bn_from_u32(b, 2);
    bn_add(c, a, b);
    puts("BN test TODO: assert 1+2==3.");
    return 0;
}
