#include "masked_types.h"
#include "masked_gadgets.h"
#include "stm32f4xx_hal.h"
#include <stdio.h>

extern void masked_keccak_round(masked_uint64_t state[5][5], uint64_t rc);

// Round constants from the Keccak spec
static const uint64_t keccak_round_constants[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL,
    0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL,
    0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL,
    0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL,
    0x0000000080000001ULL, 0x8000000080008008ULL
};

void masked_keccak_f1600(masked_uint64_t state[5][5]) {
    printf("== Before masked_keccak_f1600 ==\n");
    for (int x = 0; x < 5; x++) {
        for (int y = 0; y < 5; y++) {
            printf("State[%d][%d]:", x, y);
            for (int i = 0; i < MASKING_N; i++) {
                uint32_t hi = (uint32_t)(state[x][y].share[i] >> 32);
                uint32_t lo = (uint32_t)(state[x][y].share[i] & 0xFFFFFFFF);
                printf(" %08lX%08lX", hi, lo);
            }
            printf("\n");
        }
    }

    for (int i = 0; i < 24; i++) {
        masked_keccak_round(state, keccak_round_constants[i]);
    }

    printf("== After masked_keccak_f1600 ==\n");
    for (int x = 0; x < 5; x++) {
        for (int y = 0; y < 5; y++) {
            printf("State[%d][%d]:", x, y);
            for (int i = 0; i < MASKING_N; i++) {
                uint32_t hi = (uint32_t)(state[x][y].share[i] >> 32);
                uint32_t lo = (uint32_t)(state[x][y].share[i] & 0xFFFFFFFF);
                printf(" %08lX%08lX", hi, lo);
            }
            printf("\n");
        }
    }
}
