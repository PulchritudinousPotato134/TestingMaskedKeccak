
#include <stdint.h>
#include <stdio.h>       // for printf
#include "masked_gadgets.h"
#include "params.h"
#include "keccak.h"

int test_masked_chi_against_reference_keccak(void) {
    int fail_count = 0;

    // 1. Initialize known Keccak state (25 lanes)
    uint64_t input_state[25];
    for (int i = 0; i < 25; i++) {
        input_state[i] = i * 0x123456789ABCDEFULL;
    }

    // 2. Copy and run reference chi() on unmasked state
    uint64_t reference_state[25];
    memcpy(reference_state, input_state, sizeof(input_state));
    chi(reference_state); // from your reference keccak.c

    // 3. Build 5x5 masked input
    masked_uint64_t masked_in[5][5];
    for (int y = 0; y < 5; y++) {
        for (int x = 0; x < 5; x++) {
            uint64_t val = input_state[y * 5 + x];
            uint64_t tmp = val;
            for (int i = 1; i < MASKING_N; i++) {
                masked_in[x][y].share[i] = get_random64();
                tmp ^= masked_in[x][y].share[i];
            }
            masked_in[x][y].share[0] = tmp;
        }
    }

    // 4. Allocate output + randomness and run masked Chi
    masked_uint64_t masked_out[5][5];
    uint64_t r[5][5][MASKING_N][MASKING_N];
    for (int y = 0; y < 5; y++)
        for (int x = 0; x < 5; x++)
            fill_random_matrix(r[x][y]);

    masked_chi_outofplace(masked_out, masked_in, r);

    // 5. Compare each output lane
    for (int y = 0; y < 5; y++) {
        for (int x = 0; x < 5; x++) {
            uint64_t recombined = 0;
            for (int i = 0; i < MASKING_N; i++) {
                recombined ^= masked_out[x][y].share[i];
            }

            uint64_t expected = reference_state[y * 5 + x];
            if (recombined != expected) {
                uint32_t rh = (uint32_t)(recombined >> 32);
                uint32_t rl = (uint32_t)(recombined & 0xFFFFFFFF);
                uint32_t eh = (uint32_t)(expected >> 32);
                uint32_t el = (uint32_t)(expected & 0xFFFFFFFF);

                printf("FAIL: RefChi[%d][%d] mismatch\r\n", x, y);
                printf("  Got:      %08lX%08lX\r\n", (unsigned long)rh, (unsigned long)rl);
                printf("  Expected: %08lX%08lX\r\n", (unsigned long)eh, (unsigned long)el);
                fail_count++;
            }
        }
    }

    if (fail_count == 0) {
        printf("PASS: test_masked_chi_against_reference_keccak passed.\r\n");
    }

    return fail_count;
}


void masked_chi_outofplace(masked_uint64_t out[5][5],
                           const masked_uint64_t in[5][5],
                           const uint64_t r[5][5][MASKING_N][MASKING_N]) {
    for (int y = 0; y < 5; y++) {
        for (int x = 0; x < 5; x++) {
            const masked_uint64_t *a = &in[x][y];
            const masked_uint64_t *b = &in[(x + 1) % 5][y];
            const masked_uint64_t *c = &in[(x + 2) % 5][y];
            masked_uint64_t t1, t2;

            masked_not(&t1, b);
            masked_and(&t2, &t1, c, r[x][y]);
            masked_xor(&out[x][y], a, &t2);
        }
    }
}

int test_masked_chi_outofplace_single_lanes(void) {
    int fail_count = 0;

    // 1. Known unmasked input
    uint64_t ref[5][5];
    for (int y = 0; y < 5; y++)
        for (int x = 0; x < 5; x++)
            ref[x][y] = (uint64_t)(x + 5 * y) * 0x1111111111111111ULL;

    // 2. Mask it
    masked_uint64_t masked_in[5][5];
    for (int y = 0; y < 5; y++) {
        for (int x = 0; x < 5; x++) {
            uint64_t val = ref[x][y];
            uint64_t temp = val;
            for (int i = 1; i < MASKING_N; i++) {
                masked_in[x][y].share[i] = get_random64();
                temp ^= masked_in[x][y].share[i];
            }
            masked_in[x][y].share[0] = temp;
        }
    }

    // 3. Allocate output + randomness
    masked_uint64_t masked_out[5][5];
    uint64_t r[5][5][MASKING_N][MASKING_N];
    for (int y = 0; y < 5; y++)
        for (int x = 0; x < 5; x++)
            fill_random_matrix(r[x][y]);

    // 4. Apply masked Chi
    masked_chi_outofplace(masked_out, masked_in, r);

    // 5. Check each output lane
    for (int y = 0; y < 5; y++) {
        for (int x = 0; x < 5; x++) {
            // Recombine masked output
            uint64_t recombined = 0;
            for (int i = 0; i < MASKING_N; i++) {
                recombined ^= masked_out[x][y].share[i];
            }

            // Compute expected Chi output
            uint64_t a = ref[x][y];
            uint64_t b = ref[(x + 1) % 5][y];
            uint64_t c = ref[(x + 2) % 5][y];
            uint64_t expected = a ^ ((~b) & c);

            if (recombined != expected) {
                uint32_t re_hi = (uint32_t)(recombined >> 32);
                uint32_t re_lo = (uint32_t)(recombined & 0xFFFFFFFF);
                uint32_t ex_hi = (uint32_t)(expected >> 32);
                uint32_t ex_lo = (uint32_t)(expected & 0xFFFFFFFF);

                printf("FAIL: Chi[%d][%d]\r\n", x, y);
                printf("  Got:     %08lX%08lX\r\n", (unsigned long)re_hi, (unsigned long)re_lo);
                printf("  Expected:%08lX%08lX\r\n", (unsigned long)ex_hi, (unsigned long)ex_lo);
                fail_count++;
            }
        }
    }

    if (fail_count == 0) {
        printf("PASS: test_masked_chi_outofplace_single_lanes passed.\r\n");
    }

    return fail_count;
}
