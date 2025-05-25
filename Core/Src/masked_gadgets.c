#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "masked_types.h"
#include "masked_gadgets.h"
#include "global_rng.h"
#include "stm32f4xx_hal_rng.h"

// === RANDOMNESS ===
void fill_random_matrix(uint64_t r[MASKING_N][MASKING_N]) {
    for (size_t i = 0; i < MASKING_N; i++) {
        for (size_t j = i + 1; j < MASKING_N; j++) {
            uint64_t val = get_random64();
            r[i][j] = val;
            r[j][i] = val;  // Symmetric entry
        }
        r[i][i] = 0;  // Diagonal not used
    }
}

// === BOOLEAN MASKING ===
void boolean_mask(uint64_t out[MASKING_N], uint64_t value) {
    uint64_t tmp = value;
    for (int i = 0; i < MASKING_N - 1; i++) {
        out[i] = get_random64();
        tmp ^= out[i];
    }
    out[MASKING_N - 1] = tmp;
}

void refresh_xor_partial(uint64_t *shares, size_t n) {
    uint64_t acc = 0;
    for (size_t i = 0; i < n - 1; i++) {
        uint64_t r = get_random64();
        shares[i] ^= r;
        acc ^= r;
    }
    shares[n - 1] ^= acc;
}

void refresh_xor(uint64_t shares[MASKING_N]) {
    uint64_t before = 0, after = 0, acc = 0;
    for (int i = 0; i < MASKING_N; i++) before ^= shares[i];
    for (int i = 0; i < MASKING_N - 1; i++) {
        uint64_t r = get_random64();
        shares[i] ^= r;
        acc ^= r;
    }
    shares[MASKING_N - 1] ^= acc;
    for (int i = 0; i < MASKING_N; i++) after ^= shares[i];
    if (before != after) {
        printf("!!! refresh_xor broke the XOR !!!\n");
        printf("Before: %lu, After: %lu\n", (uint32_t)before, (uint32_t)after);
        for (int i = 0; i < MASKING_N; i++) {
            printf("shares[%d] = %lu\n", i, (uint32_t)shares[i]);
        }
        while (1);
    }
}

// === BOOLEAN GADGETS ===
void masked_xor(masked_uint64_t *out, const masked_uint64_t *a, const masked_uint64_t *b) {
    for (size_t i = 0; i < MASKING_N; i++) {
        out->share[i] = a->share[i] ^ b->share[i];
    }
}

void masked_and(masked_uint64_t *out, const masked_uint64_t *a, const masked_uint64_t *b, const uint64_t r[MASKING_N][MASKING_N]) {
    for (size_t i = 0; i < MASKING_N; i++) {
        out->share[i] = a->share[i] & b->share[i];
    }
    for (size_t i = 0; i < MASKING_N; i++) {
        for (size_t j = i + 1; j < MASKING_N; j++) {
            uint64_t cross = (a->share[i] & b->share[j]) ^ (a->share[j] & b->share[i]);
            out->share[i] ^= r[i][j];
            out->share[j] ^= cross ^ r[i][j];
        }
    }
}

void masked_not(masked_uint64_t *dst, const masked_uint64_t *src) {
    for (size_t i = 0; i < MASKING_N; ++i)
        dst->share[i] = ~src->share[i];

    uint64_t orig = 0, inv = 0;
    for (size_t i = 0; i < MASKING_N; ++i) {
        orig ^= src->share[i];
        inv  ^= dst->share[i];
    }
    dst->share[0] ^= inv ^ ~orig;
}

// === ARITHMETIC GADGETS ===
void masked_add_arithmetic(masked_uint64_t *out, const masked_uint64_t *a, const masked_uint64_t *b) {
    for (size_t i = 0; i < MASKING_N; i++) {
        out->share[i] = a->share[i] + b->share[i];
    }
}

void masked_sub_arithmetic(masked_uint64_t *out, const masked_uint64_t *a, const masked_uint64_t *b) {
    for (size_t i = 0; i < MASKING_N; i++) {
        out->share[i] = a->share[i] - b->share[i];
    }
}

void masked_mul_arithmetic(masked_uint64_t *out, const masked_uint64_t *a, const masked_uint64_t *b, const uint64_t r[MASKING_N][MASKING_N]) {
    for (size_t i = 0; i < MASKING_N; i++) {
        out->share[i] = a->share[i] * b->share[i];
    }
    for (size_t i = 0; i < MASKING_N; i++) {
        for (size_t j = i + 1; j < MASKING_N; j++) {
            uint64_t t = a->share[i] * b->share[j] + a->share[j] * b->share[i];
            out->share[i] += r[i][j];
            out->share[j] += t - r[i][j];
        }
    }
}

void masked_neg_arithmetic(masked_uint64_t *out, const masked_uint64_t *a) {
    for (size_t i = 0; i < MASKING_N; i++) {
        out->share[i] = -a->share[i];
    }
}

// === CONVERSIONS ===
void SecA2Bq(uint64_t *out, const uint64_t *in, size_t n, uint64_t q) {
    if (n == 1) {
        out[0] = in[0] % q;
        for (size_t i = 1; i < MASKING_N; i++) out[i] = 0;
        return;
    }
    size_t half = n / 2;
    uint64_t y[MASKING_N] = {0};
    uint64_t z[MASKING_N] = {0};
    SecA2Bq_debug(y, in, half, q);
    SecA2Bq_debug(z, in + half, n - half, q);
    refresh_xor_partial(y, half);
    refresh_xor_partial(z, n - half);
    SecAddModp(out, y, z, q);
}

void SecB2Aq(uint64_t *out, const uint64_t *in, size_t n, uint64_t q) {
    uint64_t x = in[0];
    for (size_t i = 1; i < n; i++) x ^= in[i];
    x = x % q;
    uint64_t sum = 0;
    for (size_t i = 0; i < n - 1; i++) {
        out[i] = get_random64() % q;
        sum = (sum + out[i]) % q;
    }
    out[n - 1] = (x + q - sum) % q;
}

void SecAddModp(uint64_t out[MASKING_N], const uint64_t a[MASKING_N], const uint64_t b[MASKING_N], uint64_t q) {
    if (q == 0) while (1) {}  // hard fault: invalid modulus
    uint64_t x = 0, y = 0;
    for (int i = 0; i < MASKING_N; i++) {
        x ^= a[i];
        y ^= b[i];
    }
    uint64_t result = (x + y) % q;
    boolean_mask(out, result);
}
