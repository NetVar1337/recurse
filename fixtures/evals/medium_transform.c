// Tier 2 — MEDIUM: per-character arithmetic against an encoded constant.
// Requires reading the transform (decompile/disasm) or differential
// observation through breakpoints; not visible in strings.
#include <stdio.h>
static const int enc[8] = { 86, 93, 84, 122, 87, 92, 89, 118 };
int main(void) {
    char buf[32] = {0};
    printf("key: ");
    if (!fgets(buf, sizeof buf, stdin)) return 1;
    for (int i = 0; i < 8; i++) {
        if ((buf[i] ^ 0x20) + 3 != enc[i]) { puts("denied"); return 1; }
    }
    puts("ACCESS GRANTED");
    return 0;
}
