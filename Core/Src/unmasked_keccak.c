#include <stdint.h>
#include "structs.h"  // for keccak_state

#define ROL64(a, offset) (((a) << (offset)) ^ ((a) >> (64 - (offset))))

static const uint64_t RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
    0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

static const uint8_t r[5][5] = {
    {  0, 36,  3, 41, 18},
    {  1, 44, 10, 45,  2},
    { 62,  6, 43, 15, 61},
    { 28, 55, 25, 21, 56},
    { 27, 20, 39,  8, 14}
};

void keccak_f1600(keccak_state *state) {
    uint64_t *s = state->s;

    for (int round = 0; round < 24; ++round) {
        // === Theta ===
        uint64_t C[5], D[5];
        for (int x = 0; x < 5; ++x)
            C[x] = s[x] ^ s[x + 5] ^ s[x + 10] ^ s[x + 15] ^ s[x + 20];

        for (int x = 0; x < 5; ++x) {
            D[x] = C[(x + 4) % 5] ^ ROL64(C[(x + 1) % 5], 1);
            for (int y = 0; y < 5; ++y)
                s[x + 5 * y] ^= D[x];
        }

        // === Rho and Pi ===
        uint64_t B[25];
        for (int x = 0; x < 5; ++x) {
            for (int y = 0; y < 5; ++y) {
                int newX = y;
                int newY = (2 * x + 3 * y) % 5;
                B[newX + 5 * newY] = ROL64(s[x + 5 * y], r[x][y]);
            }
        }

        // === Chi ===
        for (int x = 0; x < 5; ++x) {
            for (int y = 0; y < 5; ++y) {
                s[x + 5 * y] = B[x + 5 * y] ^ ((~B[(x + 1) % 5 + 5 * y]) & B[(x + 2) % 5 + 5 * y]);
            }
        }

        // === Iota ===
        s[0] ^= RC[round];
    }

    state->pos = 0;  // Reset sponge position after permutation
}
