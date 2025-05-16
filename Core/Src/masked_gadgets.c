#include "masked_types.h"
#include "global_rng.h"  // ensure this includes `extern RNG_HandleTypeDef hrng`
#include "stm32f4xx_hal_rng.h"  // required for HAL RNG
#include <stddef.h>  // for size_t
#include <stdint.h>
#include <stdio.h>
#include "masked_gadgets.h"  // Make sure this includes definitions for masked_xor, masked_and, fill_random_matrix
#include <inttypes.h>

// Utility function to recombine shares
uint64_t recombineForTest(const masked_uint64_t* m) {
    uint64_t r = 0;
    for (int i = 0; i < MASKING_N; i++) r ^= m->share[i];
    return r;
}

int test_masked_and_exhaustive_safe(void) {
    int fail_count = 0;
    const uint64_t test_vals[][2] = {
        {0x0000000000000000ULL, 0x0000000000000000ULL},
        {0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL},
        {0xFFFFFFFFFFFFFFFFULL, 0x0000000000000000ULL},
        {0xAAAAAAAAAAAAAAAAULL, 0x5555555555555555ULL},
        {0x123456789ABCDEF0ULL, 0x0F0F0F0F0F0F0F0FULL},
        {0xFFFF0000FFFF0000ULL, 0x00FF00FF00FF00FFULL}, // your original
    };

    for (int t = 0; t < sizeof(test_vals) / sizeof(test_vals[0]); t++) {
        masked_uint64_t a = {0}, b = {0}, result = {0};
        uint64_t r[MASKING_N][MASKING_N];
        uint64_t a_val = test_vals[t][0];
        uint64_t b_val = test_vals[t][1];

        // Generate masked shares
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

        // Fill randomness and compute
        fill_random_matrix(r);
        masked_and(&result, &a, &b, r);

        // Recombine
        uint64_t recombined = 0;
        for (int i = 0; i < MASKING_N; i++) {
            recombined ^= result.share[i];
        }

        uint64_t expected = a_val & b_val;
        if (recombined != expected) {
            printf("FAIL [and_exh %d]: a=0x%016" PRIx64 " & b=0x%016" PRIx64
                   " → got 0x%016" PRIx64 ", expected 0x%016" PRIx64 "\n",
                   t, a_val, b_val, recombined, expected);
            fail_count++;
        }
    }

    if (fail_count == 0) {
        printf("PASS: test_masked_and_exhaustive_safe all tests passed.\n");
    }

    return fail_count;
}

int test_masked_and_identity_safe(void) {
    int fails = 0;
    uint64_t identity_cases[] = {
        0x0000000000000000ULL,
        0xFFFFFFFFFFFFFFFFULL,
        0xAAAAAAAAAAAAAAAAULL,
        0x123456789ABCDEF0ULL,
    };

    for (int i = 0; i < sizeof(identity_cases)/sizeof(identity_cases[0]); i++) {
        uint64_t x_val = identity_cases[i];

        // x & 0 == 0
        masked_uint64_t a = {0}, b = {0}, result = {0};
        uint64_t r[MASKING_N][MASKING_N];
        uint64_t a_combined = x_val;

        for (int s = 1; s < MASKING_N; s++) {
            a.share[s] = get_random64();
            a_combined ^= a.share[s];
        }
        a.share[0] = a_combined;

        for (int s = 0; s < MASKING_N; s++) {
            b.share[s] = 0;
        }

        fill_random_matrix(r);
        masked_and(&result, &a, &b, r);

        uint64_t recombined = 0;
        for (int s = 0; s < MASKING_N; s++) {
            recombined ^= result.share[s];
        }

        if (recombined != 0) {
            printf("FAIL: x=0x%016" PRIx64 " & 0 → got 0x%016" PRIx64 "\n", x_val, recombined);
            fails++;
        }

        // x & ~0 == x
        for (int s = 0; s < MASKING_N; s++) {
            b.share[s] = (s == 0) ? 0xFFFFFFFFFFFFFFFFULL : 0;
        }

        fill_random_matrix(r);
        masked_and(&result, &a, &b, r);

        recombined = 0;
        for (int s = 0; s < MASKING_N; s++) {
            recombined ^= result.share[s];
        }

        if (recombined != x_val) {
            printf("FAIL: x=0x%016" PRIx64 " & ~0 → got 0x%016" PRIx64 "\n", x_val, recombined);
            fails++;
        }
    }

    if (fails == 0) {
        printf("PASS: test_masked_and_identity_safe passed.\n");
    }

    return fails;
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
                const uint64_t r[MASKING_N][MASKING_N])
{
    /* diagonal terms --------------------------------------------------- */
    for (size_t i = 0; i < MASKING_N; ++i)
        out->share[i] = a->share[i] & b->share[i];

    /* cross terms ------------------------------------------------------ */
    for (size_t i = 0; i < MASKING_N; ++i)
        for (size_t j = i + 1; j < MASKING_N; ++j) {

            uint64_t rij   = r[i][j];

            uint64_t t_ij  = (a->share[i] & b->share[j]) ^ rij;
            uint64_t t_ji  = (a->share[j] & b->share[i]) ^ rij;

            out->share[i] ^= t_ij;   /* add to share i */
            out->share[j] ^= t_ji;   /* add to share j */
        }
}


