// Tier 1 — EASY: static comparison against a literal.
// Solvable by strings/xrefs alone; the flag is embedded plaintext.
#include <stdio.h>
#include <string.h>
int main(void) {
    char buf[32] = {0};
    printf("key: ");
    if (!fgets(buf, sizeof buf, stdin)) return 1;
    buf[strcspn(buf, "\n")] = 0;
    if (strcmp(buf, "RECURSE{plaintext_rookie}") == 0)
        puts("ACCESS GRANTED");
    else
        puts("denied");
    return 0;
}
