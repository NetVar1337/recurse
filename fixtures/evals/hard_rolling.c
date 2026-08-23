// Tier 3 — HARD: rolling XOR keyed by previous byte and index; one wrong
// character corrupts everything after it (no per-position feedback).
#include <stdio.h>
static const unsigned char enc[12] =
    { 0x3d, 0x25, 0x6f, 0x33, 0x71, 0x2a, 0x5d, 0x24, 0x63, 0x39, 0x7a, 0x21 };
int main(void) {
    unsigned char prev = 0x42;
    unsigned char in[16] = {0};
    printf("key: ");
    if (!fgets((char *)in, sizeof in, stdin)) return 1;
    for (int i = 0; i < 12; i++) {
        unsigned char k = (unsigned char)((in[i] ^ prev) + i);
        if (k != enc[i]) { puts("denied"); return 1; }
        prev = enc[i];
    }
    puts("ACCESS GRANTED");
    return 0;
}
