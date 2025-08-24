// misc/hexbytes_to_u32words.c
#include <ctype.h>
#include <stdint.h>
#include <stdio.h>

int main(void) {
    // read hex bytes like: 0x12,0x34,0x56,...
    unsigned b[4096];
    int      c, n = 0, v = 0, have = 0;
    while ((c = getchar()) != EOF) {
        if (isxdigit(c)) {
            v = (v << 4) | (c <= '9' ? c - '0' : (tolower(c) - 'a' + 10));
            have ^= 1;
            if (have == 0) {
                b[n++] = v;
                v      = 0;
            }
        }
    }
    // left-pad to multiple of 4 bytes
    int pad = (4 - (n % 4)) & 3;
    for (int i = 0; i < pad; i++)
        putchar('\n');  // just consume; we’ll print words next

    // print 32-bit words MSB first
    int words = (n + pad) / 4;
    if (words != 32)
        fprintf(stderr, "[warn] got %d words; expect 32 for 1024-bit\n", words);
    printf("/* %d bytes -> %d words */\n", n, words);
    for (int i = 0; i < words; i++) {
        uint32_t w = (b[4 * i] << 24) | (b[4 * i + 1] << 16)
                     | (b[4 * i + 2] << 8) | b[4 * i + 3];
        printf("0x%08X%s", w, (i + 1 < words) ? ", " : "\n");
        if ((i + 1) % 4 == 0)
            printf("\n");
    }
    return 0;
}
