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
    masked_uint64_t C[5], D[5];

    for (int x = 0; x < 5; x++) {
        C[x] = state[x][0];
        for (int y = 1; y < 5; y++) {
            masked_xor(&C[x], &C[x], &state[x][y]);
        }
    }

    for (int x = 0; x < 5; x++) {
        masked_uint64_t rot;
        for (int i = 0; i < MASKING_N; i++) {
            rot.share[i] = (C[(x + 1) % 5].share[i] << 1) |
                           (C[(x + 1) % 5].share[i] >> (64 - 1));
        }
        masked_xor(&D[x], &C[(x + 4) % 5], &rot);
    }

    for (int x = 0; x < 5; x++) {
        for (int y = 0; y < 5; y++) {
            masked_xor(&state[x][y], &state[x][y], &D[x]);
        }
    }
}

// === RHO ===
static const uint8_t keccak_rho_offsets[5][5] = {
    {  0,  36,   3, 105, 210 },
    {  1, 300,  10,  45,  66 },
    {190,   6, 153,  15, 253 },
    { 28,  55, 276,  91, 136 },
    { 91, 276, 231, 120,  78 }
};

void masked_rho(masked_uint64_t state[5][5]) {
    for (int x = 0; x < 5; x++) {
        for (int y = 0; y < 5; y++) {
            uint8_t r = keccak_rho_offsets[x][y];
            for (int i = 0; i < MASKING_N; i++) {
                uint64_t value = state[x][y].share[i];
                state[x][y].share[i] = (value << r) | (value >> (64 - r));
            }
        }
    }
}

// === PI ===
void masked_pi(masked_uint64_t state[5][5]) {
    masked_uint64_t temp[5][5];

    for (int x = 0; x < 5; x++) {
        for (int y = 0; y < 5; y++) {
            temp[x][y] = state[x][y];
        }
    }

    for (int x = 0; x < 5; x++) {
        for (int y = 0; y < 5; y++) {
            state[y][(2 * x + 3 * y) % 5] = temp[x][y];
        }
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
    // Split rc into shares that XOR to rc
    uint64_t r[MASKING_N];
    r[0] = rc;
    for (int i = 1; i < MASKING_N; i++) {
        r[i] = get_random64();       // Get a fresh random share
        r[0] ^= r[i];                // Ensure all shares XOR to original rc
    }

    for (int i = 0; i < MASKING_N; i++) {
        state[0][0].share[i] ^= r[i];
    }
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

