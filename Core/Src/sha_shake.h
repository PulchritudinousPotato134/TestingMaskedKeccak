#ifndef MASKED_KECCAK_H
#define MASKED_KECCAK_H

#include <stddef.h>
#include <stdint.h>
#include "masked_types.h"

#ifdef __cplusplus
extern "C" {
#endif



// === Unified low-level sponge hash interface ===
// Uses Keccak-f[1600] in a masked domain.
//
// Parameters:
//   - output: where to write the hash/XOF output
//   - output_len: how many bytes to produce
//   - input: pointer to input message
//   - input_len: message length in bytes
//   - rate: bitrate in bytes (e.g. 168 for SHAKE128)
//   - domain_separator: domain byte (e.g. 0x06 or 0x1F)
//
// This function absorbs the input, appends domain/padding,
// then squeezes the requested number of output bytes.
// --- Fixed-length SHA3 hash functions ---

void masked_keccak_sponge(uint8_t *output, size_t output_len,
                          const uint8_t *input, size_t input_len,
                          size_t rate, uint8_t domain_sep);
/**
 * Computes SHA3-224 (28 bytes output) using masked Keccak.
 * @param output Buffer to receive 28-byte hash.
 * @param input Message to hash.
 * @param input_len Length of input in bytes.
 */
void masked_sha3_224(uint8_t *output, const uint8_t *input, size_t input_len);

/**
 * Computes SHA3-256 (32 bytes output) using masked Keccak.
 */
void masked_sha3_256(uint8_t *output, const uint8_t *input, size_t input_len);

/**
 * Computes SHA3-384 (48 bytes output) using masked Keccak.
 */
void masked_sha3_384(uint8_t *output, const uint8_t *input, size_t input_len);

/**
 * Computes SHA3-512 (64 bytes output) using masked Keccak.
 */
void masked_sha3_512(uint8_t *output, const uint8_t *input, size_t input_len);

// --- Extendable Output Functions (XOFs) ---

/**
 * Computes SHAKE128 (XOF), which produces arbitrary-length output.
 * @param output Buffer to receive output.
 * @param output_len Number of bytes of output desired.
 * @param input Message to process.
 * @param input_len Length of input in bytes.
 */
void masked_shake128(uint8_t *output, size_t output_len,
                     const uint8_t *input, size_t input_len);

/**
 * Computes SHAKE256 (XOF), which produces arbitrary-length output.
 */
void masked_shake256(uint8_t *output, size_t output_len,
                     const uint8_t *input, size_t input_len);

#ifdef __cplusplus
}
#endif

#endif // MASKED_KECCAK_H
