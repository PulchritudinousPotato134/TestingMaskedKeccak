#ifndef MASKED_KECCAK_H
#define MASKED_KECCAK_H

#include <stddef.h>
#include <stdint.h>
#include "masked_types.h"

// === Round Functions ===
void masked_theta(masked_uint64_t state[5][5]);
void masked_rho(masked_uint64_t state[5][5]);
void masked_pi(masked_uint64_t state[5][5]);
void masked_chi(masked_uint64_t out[5][5], const masked_uint64_t in[5][5],
                const uint64_t r[5][5][MASKING_N][MASKING_N]);
void masked_iota(masked_uint64_t state[5][5], uint64_t rc);
void masked_keccak_round(masked_uint64_t state[5][5], uint64_t rc);

// === Sponge Construction ===
void masked_absorb(masked_uint64_t state[5][5], const uint8_t *input, size_t input_len, size_t rate);
void masked_squeeze(uint8_t *output, size_t output_len, masked_uint64_t state[5][5], size_t rate);

// === Permutation Wrapper ===
void masked_keccak_f1600(masked_uint64_t state[5][5]);

// === Hash Function Interfaces ===
void masked_sha3_256(uint8_t *output, const uint8_t *input, size_t input_len);
void masked_sha3_512(uint8_t *output, const uint8_t *input, size_t input_len);
void masked_shake128(uint8_t *output, size_t output_len, const uint8_t *input, size_t input_len);
void masked_shake256(uint8_t *output, size_t output_len, const uint8_t *input, size_t input_len);

// === Utility ===
void print_recombined_state(masked_uint64_t state[5][5], const char *label);
uint64_t get_random64(void);
void masked_value_set(masked_uint64_t *out, uint64_t value);

#endif // MASKED_KECCAK_H
