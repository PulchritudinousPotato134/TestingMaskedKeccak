#ifndef MASKED_KECCAK_H
#define MASKED_KECCAK_H

#include <stddef.h>
#include <stdint.h>
#include "masked_types.h"
#include "structs.h"

extern const uint64_t RC[24];

// === Round Functions ===
void masked_theta(masked_uint64_t state[5][5]);
void masked_rho(masked_uint64_t state[5][5]);
void masked_pi(masked_uint64_t state[5][5]);
void masked_chi(masked_uint64_t out[5][5], const masked_uint64_t in[5][5],
                const uint64_t r[5][5][MASKING_N][MASKING_N]);
void masked_iota(masked_uint64_t state[5][5], uint64_t rc);
void masked_keccak_round(masked_uint64_t state[5][5], uint64_t rc);
void masked_keccak_f1600(masked_uint64_t state[5][5]);

// === Sponge Construction ===
void masked_absorb(masked_uint64_t state[5][5], const uint8_t *input, size_t input_len, size_t rate);
void masked_squeeze(uint8_t *output, size_t output_len, masked_uint64_t state[5][5], size_t rate);
//UNNMASKED
void unmasked_absorb(keccak_state state, const uint8_t *input, size_t input_len, size_t rate);
void unmasked_shake128_squeezeblocks(uint8_t *output, size_t nblocks, keccak_state *state);

// === Stateful Sponge / Block Based Squeeze ===
void masked_shake128_absorb_once(masked_keccak_state *ctx,
                                 const uint8_t *input, size_t input_len);
void masked_shake128_squeezeblocks(uint8_t *output, size_t nblocks,
                                   masked_keccak_state *ctx);

// === Permutation Wrapper ===
void masked_keccak_f1600(masked_uint64_t state[5][5]);

// === Hash Function Interfaces ===
void masked_sha3_256(uint8_t *output, const uint8_t *input, size_t input_len);
void masked_sha3_512(uint8_t *output, const uint8_t *input, size_t input_len);
void masked_shake128(uint8_t *output, size_t output_len, const uint8_t *input, size_t input_len);
void masked_shake256(uint8_t *output, size_t output_len, const uint8_t *input, size_t input_len);

// === Utility ===
void print_recombined_state(masked_uint64_t state[5][5], const char *label);
void masked_value_set(masked_uint64_t *out, uint64_t value);

// ~~~ ARITHMETIC VERSION ~~~

// === Round Functions ARITHMETIC ===
void masked_theta_arithmetic(masked_uint64_t state[5][5]);
void masked_rho_arithmetic(masked_uint64_t state[5][5]);
void masked_pi_arithmetic(masked_uint64_t state[5][5]);
void masked_chi_arithmetic(masked_uint64_t out[5][5], const masked_uint64_t in[5][5],
                           const uint64_t r[5][5][MASKING_N][MASKING_N]);
void masked_iota_arithmetic(masked_uint64_t state[5][5], uint64_t rc);
void masked_keccak_round_arithmetic(masked_uint64_t state[5][5], uint64_t rc);

// === Permutation Wrapper ARITHMETIC ===
void masked_keccak_f1600_arithmetic(masked_uint64_t state[5][5]);

void masked_shake128_absorb_arithmetic(masked_uint64_t state[5][5], const uint8_t *input, size_t input_len, size_t rate);
void masked_shake128_squeezeblocks_arithmetic(uint8_t *output, size_t output_len, masked_uint64_t state[5][5], size_t rate);

// === Hash Function Interfaces ===
void masked_sha3_256_arithmetic(uint8_t *output, const uint8_t *input, size_t input_len);
void masked_sha3_512_arithmetic(uint8_t *output, const uint8_t *input, size_t input_len);
void masked_shake128_arithmetic(uint8_t *output, size_t output_len, const uint8_t *input, size_t input_len);
void masked_shake256_arithmetic(uint8_t *output, size_t output_len, const uint8_t *input, size_t input_len);

// === Utility ===
void print_recombined_state_arithmetic(masked_uint64_t state[5][5], const char *label);
void masked_value_set_arithmetic(masked_uint64_t *out, uint64_t value);

#endif // MASKED_KECCAK_H
