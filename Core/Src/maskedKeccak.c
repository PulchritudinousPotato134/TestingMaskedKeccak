#include "masked_types.h"
#include "masked_gadgets.h"
#include "stm32f4xx_hal.h"
#include "debug_log.h"// for HAL_RNG
  // or your specific STM32 HAL header

extern RNG_HandleTypeDef hrng;

uint64_t get_random64(void) {
    uint32_t r1, r2;
    HAL_RNG_GenerateRandomNumber(&hrng, &r1);
    HAL_RNG_GenerateRandomNumber(&hrng, &r2);
    return ((uint64_t)r1 << 32) | r2;
}

// === THETA ===
void masked_theta(masked_uint64_t state[5][5]) {
    masked_uint64_t C[5] = {0};
    masked_uint64_t D[5] = {0};

    // === Compute C[x] = A[x][0] ^ A[x][1] ^ ... ^ A[x][4] ===
    for (int x = 0; x < 5; x++) {
        C[x] = state[x][0];
        for (int y = 1; y < 5; y++) {
            masked_xor(&C[x], &C[x], &state[x][y]);
        }
    }

    // === Compute D[x] = C[x-1] ^ ROTL(C[x+1], 1) ===
    for (int x = 0; x < 5; x++) {
        for (int i = 0; i < MASKING_N; i++) {
            uint64_t c_plus_1 = C[(x + 1) % 5].share[i];
            uint64_t rot = (c_plus_1 << 1) | (c_plus_1 >> (64 - 1));
            D[x].share[i] = C[(x + 4) % 5].share[i] ^ rot;
        }
    }

    // === Apply D[x] to all lanes in column x ===
    for (int x = 0; x < 5; x++) {
        for (int y = 0; y < 5; y++) {
            for (int i = 0; i < MASKING_N; i++) {
                state[x][y].share[i] ^= D[x].share[i];
            }
        }
    }
}



// === RHO ===
static const uint8_t keccak_rho_offsets[5][5] = {
    {  0, 36,  3, 41, 18 },
    {  1, 44, 10, 45,  2 },
    { 62,  6, 43, 15, 61 },
    { 28, 55, 25, 21, 56 },
    { 27, 20, 39,  8, 14 }
};

static inline uint64_t rol64(uint64_t x, unsigned int n) {
    n %= 64;
    return (x << n) | (x >> ((64 - n) % 64));
}


void masked_rho(masked_uint64_t state[5][5]) {
    for (int x = 0; x < 5; x++) {
        for (int y = 0; y < 5; y++) {
            uint8_t r = keccak_rho_offsets[x][y];
            for (int i = 0; i < MASKING_N; i++) {
                uint64_t value = state[x][y].share[i];
                state[x][y].share[i] = rol64(value, r);
            }
        }
    }
}

// === PI ===
void masked_pi(masked_uint64_t state[5][5])
{
    masked_uint64_t tmp[5][5];

    /* 1. Make a copy of the current masked state ------------------------- */
    for (int x = 0; x < 5; ++x)
        for (int y = 0; y < 5; ++y)
            tmp[x][y] = state[x][y];

    /* 2. Apply the Keccak π permutation to every share ------------------- */
    for (int x = 0; x < 5; ++x)
        for (int y = 0; y < 5; ++y) {
            int new_x = y;                       /* u */
            int new_y = (2 * x + 3 * y) % 5;     /* v */
            state[new_x][new_y] = tmp[x][y];     /* moves ALL shares   */
        }

    /* 3. Re-align the mask: force XOR(shares) == share[0] ---------------- */
    for (int x = 0; x < 5; ++x)
        for (int y = 0; y < 5; ++y) {
            uint64_t parity = 0;
            for (int i = 0; i < MASKING_N; ++i)
                parity ^= state[x][y].share[i];  /* current XOR */

            /* delta = XOR(shares) ⊕ share[0]  ==  XOR(all other shares)   */
            uint64_t delta = parity ^ state[x][y].share[0];

            /* flip the bits of share[0] that are present in the other
               shares so that the overall XOR collapses to share[0] again */
            state[x][y].share[0] ^= delta;
        }
}


// === CHI ===
void masked_chi(masked_uint64_t state[5][5],
                uint64_t r[5][5][MASKING_N][MASKING_N]) {
    masked_uint64_t temp[5];

    for (int y = 0; y < 5; y++) {
        for (int x = 0; x < 5; x++) {
            temp[x] = state[x][y];
        }

        for (int x = 0; x < 5; x++) {
            masked_uint64_t notA1;
            for (int i = 0; i < MASKING_N; i++) {
                notA1.share[i] = ~temp[(x + 1) % 5].share[i];
            }

            masked_uint64_t and_result;
            masked_and(&and_result,
                       &notA1,
                       &temp[(x + 2) % 5],
                       r[x][y]);

            masked_xor(&state[x][y], &temp[x], &and_result);
        }
    }
}
void masked_iota(masked_uint64_t state[5][5], uint64_t rc) {
    state[0][0].share[0] ^= rc;
}

// Helper function (add this)
void print_recombined_state(masked_uint64_t state[5][5], const char *label) {
    printf("== %s (Recombined) ==\n", label);
    for (int x = 0; x < 5; x++) {
        for (int y = 0; y < 5; y++) {
            uint64_t val = 0;
            for (int i = 0; i < MASKING_N; i++) {
                val ^= state[x][y].share[i];
            }
            uint32_t hi = (uint32_t)(val >> 32);
            uint32_t lo = (uint32_t)(val & 0xFFFFFFFF);
            printf("State[%d][%d]: %08X%08X\n", x, y, hi, lo);
        }
    }
}


void masked_keccak_round(masked_uint64_t state[5][5], uint64_t rc) {
    // Allocate fresh randomness for Chi step
    uint64_t r_chi[5][5][MASKING_N][MASKING_N];

    // Fill randomness for each (x, y) lane
    for (int x = 0; x < 5; x++) {
        for (int y = 0; y < 5; y++) {
            fill_random_matrix(r_chi[x][y]);
        }
    }

    // Apply the five Keccak round steps
    print_recombined_state(state, "Before Theta");
    masked_theta(state);

    print_recombined_state(state, "After Theta");
    masked_rho(state);

    print_recombined_state(state, "After Rho");
    masked_pi(state);

    print_recombined_state(state, "After Pi");
    masked_chi(state, r_chi);

    print_recombined_state(state, "After Chi");
    masked_iota(state, rc);

    print_recombined_state(state, "After Iota");

}

