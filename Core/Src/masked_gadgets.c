#include "masked_types.h"
#include "global_rng.h"  // ensure this includes `extern RNG_HandleTypeDef hrng`
#include "stm32f4xx_hal_rng.h"  // required for HAL RNG
#include <stddef.h>  // for size_t
#include <stdint.h>
#include <stdio.h>
#include "masked_gadgets.h"  // Make sure this includes definitions for masked_xor, masked_and, fill_random_matrix


// Utility function to recombine shares
uint64_t recombineForTest(const masked_uint64_t* m) {
    uint64_t r = 0;
    for (int i = 0; i < MASKING_N; i++) r ^= m->share[i];
    return r;
}

// Test masked_xor and masked_and; return 0 if all pass, >0 if failures
int test_masked_and_xor(void) {
    int fail_count = 0;

    masked_uint64_t a = {0}, b = {0}, result = {0};
    uint64_t r[MASKING_N][MASKING_N];

    // Prepare known values
    uint64_t a_val = 0xFFFF0000FFFF0000;
    uint64_t b_val = 0x00FF00FF00FF00FF;

    // Expected AND: 0x00FF000000FF0000


    // Generate random shares that XOR to a_val and b_val
    uint64_t a_combined = a_val;
    uint64_t b_combined = b_val;

    for (int i = 1; i < MASKING_N; i++) {
        a.share[i] = get_random64();
        b.share[i] = get_random64();
        a_combined ^= a.share[i];
        b_combined ^= b.share[i];
    }
    a.share[0] = a_combined;
    b.share[0] = b_combined;

    // Fill randomness matrix and compute masked AND
    fill_random_matrix(r);
    masked_and(&result, &a, &b, r);

    // Recombine result and compare with unmasked AND
    uint64_t recombined = 0;
    for (int i = 0; i < MASKING_N; i++) {
        recombined ^= result.share[i];
    }

    uint64_t expected = a_val & b_val;
    if (recombined != expected) {
        printf("FAIL: masked_and gave 0x%016llX, expected 0x%016llX\n",
               recombined, expected);
        fail_count++;
    } else {
        printf("PASS: masked_and result correct.\n");
    }

    return fail_count;
}
int test_masked_xor(void) {
    masked_uint64_t a, b, result;
    uint64_t a_val = 0xAAAAAAAAAAAAAAAAULL;
    uint64_t b_val = 0x5555555555555555ULL;
    uint64_t expected = a_val ^ b_val;

    // Generate random shares for 'a'
    uint64_t acc = 0;
    for (int i = 1; i < MASKING_N; i++) {
        a.share[i] = get_random64();
        acc ^= a.share[i];
    }
    a.share[0] = a_val ^ acc;

    // Generate random shares for 'b'
    acc = 0;
    for (int i = 1; i < MASKING_N; i++) {
        b.share[i] = get_random64();
        acc ^= b.share[i];
    }
    b.share[0] = b_val ^ acc;

    // Run masked XOR
    masked_xor(&result, &a, &b);

    // Recombine
    uint64_t combined = 0;
    for (int i = 0; i < MASKING_N; i++) {
        combined ^= result.share[i];
    }

    uint32_t hi = (uint32_t)(combined >> 32);
    uint32_t lo = (uint32_t)(combined & 0xFFFFFFFF);
    uint32_t ehi = (uint32_t)(expected >> 32);
    uint32_t elo = (uint32_t)(expected & 0xFFFFFFFF);

    if (combined == expected) {
        printf("PASS: masked_xor result correct.\r\n");
        return 0;
    } else {
        printf("FAIL: masked_xor result incorrect.\r\nGot:     %08X%08X\r\nExpected: %08X%08X\r\n",
               hi, lo, ehi, elo);
        return 1;
    }
}

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


