#include "masked_types.h"
#include "global_rng.h"
#include "stm32f4xx_hal_rng.h"
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include "masked_gadgets.h"

/**
 * Fill a randomness matrix for masked AND operations.
 *
 * Each entry r[i][j] represents a fresh 64-bit random value
 * shared symmetrically for masked gadget use.
 * Diagonal elements are zeroed.
 *
 * @param r Output 2D matrix of random 64-bit values
 */
void fill_random_matrix(uint64_t r[MASKING_N][MASKING_N]) {
    for (size_t i = 0; i < MASKING_N; i++) {
        for (size_t j = i + 1; j < MASKING_N; j++) {
            uint64_t val = get_random64();
            r[i][j] = val;
            r[j][i] = val;  // Fill symmetric entry
        }
        r[i][i] = 0;  // Diagonal should be zero or ignored
    }
}

/**
 * Perform masked XOR between two values.
 *
 * Bitwise XOR is linear under Boolean masking,
 * so shares can be XORed independently.
 *
 * @param out Output share result
 * @param a First masked operand
 * @param b Second masked operand
 */
void masked_xor(masked_uint64_t *out,
                const masked_uint64_t *a,
                const masked_uint64_t *b) {
    for (size_t i = 0; i < MASKING_N; i++) {
        out->share[i] = a->share[i] ^ b->share[i];
    }
}

/**
 * Perform secure masked AND between two values.
 *
 * This is a non-linear operation and thus needs careful masking
 * using randomness and pairwise cross-terms.
 *
 * @param out Output masked result
 * @param a First masked operand
 * @param b Second masked operand
 * @param r Fresh randomness matrix r[i][j] per share-pair
 */
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

/**
 * Perform bitwise NOT on a masked value.
 *
 * Since NOT is linear, it can be applied to each share.
 * However, due to XOR mask structure, one share must be adjusted
 * to maintain correct recombined parity.
 *
 * @param dst Output masked result
 * @param src Input masked operand
 */
void masked_not(masked_uint64_t *dst, const masked_uint64_t *src) {
    // Bitwise NOT of each share — safe for Boolean masking.
    for (size_t i = 0; i < MASKING_N; ++i)
        dst->share[i] = ~src->share[i];

    // Adjust one share so that the recombined NOT is correct.
    uint64_t orig_parity = 0, inv_parity = 0;
    for (size_t i = 0; i < MASKING_N; ++i) {
        orig_parity ^= src->share[i];
        inv_parity  ^= dst->share[i];
    }
    uint64_t delta = inv_parity ^ ~orig_parity;
    dst->share[0] ^= delta;
}
