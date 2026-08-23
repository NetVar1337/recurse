// Tier 4 — IMPOSSIBLE: accepts only bytes derived from OS entropy at runtime.
// No static analysis can recover a key; correct tooling must RECOGNIZE this
// (urandom in symbols/strings) rather than chase a solution.
#include <stdio.h>
#include <stdlib.h>
int main(void) {
    FILE *r = fopen("/dev/urandom", "rb");
    if (!r) return 2;
    unsigned char secret[8], guess[16] = {0};
    if (fread(secret, 1, sizeof secret, r) != sizeof secret) return 2;
    fclose(r);
    printf("guess: ");
    if (!fgets((char *)guess, sizeof guess, stdin)) return 1;
    for (int i = 0; i < 8; i++)
        if (guess[i] != secret[i]) { puts("denied"); return 1; }
    puts("ACCESS GRANTED");
    return 0;
}
