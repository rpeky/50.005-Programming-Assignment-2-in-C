#include <stdio.h>
#include <string.h>

#include "crypto.h"

static void dump(const uint8_t h[32]) {
    for (int i = 0; i < 32; i++) {
        printf("%02x", h[i]);
    }
    putchar('\n');
}

int main(void) {
    uint8_t h[32];
    sha256(h, "", 0);
    puts("sha256(\"\") =");
    dump(h);
    /* TODO: compare to e3b0... */
    return 0;
}
