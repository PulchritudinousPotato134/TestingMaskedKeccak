#include "masked_types.h"
#include "global_rng.h"  // ensure this includes `extern RNG_HandleTypeDef hrng`
#include "stm32f4xx_hal_rng.h"  // required for HAL RNG
#include <stddef.h>  // for size_t

void fill_random_matrix(uint64_t r[MASKING_N][MASKING_N]) {
    for (size_t i = 0; i < MASKING_N; i++) {
        for (size_t j = i + 1; j < MASKING_N; j++) {
            uint64_t val = get_random64();
            r[i][j] = val;
            r[j][i] = val;  // Fill symmetric entry!
        }
        r[i][i] = 0;  // Diagonal should be zero or ignored
    }
}



void masked_xor(masked_uint64_t *out,
                const masked_uint64_t *a,
                const masked_uint64_t *b) {
    for (size_t i = 0; i < MASKING_N; i++) {
        out->share[i] = a->share[i] ^ b->share[i];
    }
}

void masked_and(masked_uint64_t *out,
                const masked_uint64_t *a,
                const masked_uint64_t *b,
                const uint64_t r[MASKING_N][MASKING_N]) {
    // Step 1: Initialize with diagonal terms
    for (size_t i = 0; i < MASKING_N; i++) {
        out->share[i] = a->share[i] & b->share[i];
    }

    // Step 2: Add cross terms with proper masking
    for (size_t i = 0; i < MASKING_N; i++) {
        for (size_t j = i + 1; j < MASKING_N; j++) {
            uint64_t cross_term = (a->share[i] & b->share[j]) ^
                                 (a->share[j] & b->share[i]);

            // Distribute the random mask correctly
            out->share[i] ^= r[i][j];
            out->share[j] ^= cross_term ^ r[i][j];
        }
    }
}


