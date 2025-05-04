/*
 * Logic taken from pqm4_masked
 * Copyright 2022 UCLouvain, Belgium and PQM4 contributors
 *
 * This file is part of pqm4_masked.
 *
 * pqm4_masked is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free
 * Software Foundation, version 3.
 *
 * pqm4_masked is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * pqm4_masked. If not, see <https://www.gnu.org/licenses/>.
 */
/* Based on the implementation "libkeccak-tiny" by David Leon Gil.
 * available at https://github.com/coruus/keccak-tiny under CC0 License.
 * */

#include "stm32f4xx_hal.h"       // includes all HAL modules
#include "stm32f4xx_hal_conf.h"  // this should include hal_def.h as well

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "maskedKeccak.h"
#include "structs.h"
#include <stdio.h>
#include <inttypes.h>

extern RNG_HandleTypeDef hrng;

typedef union {
  uint64_t w[MASKING_N][KECCAK_NWORDS];
  uint32_t h[MASKING_N][2 * KECCAK_NWORDS];
} MaskedKeccakState;

/******** The Keccak-f[1600] permutation ********/

/*** Constants. ***/
static const uint8_t rho[24] = {1,  3,  6,  10, 15, 21, 28, 36, 45, 55, 2,  14,
                                27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44};
static const uint8_t pi[24] = {10, 7,  11, 17, 18, 3, 5,  16, 8,  21, 24, 4,
                               15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6,  1};
static const uint64_t RC[24] = {1ULL,
                                0x8082ULL,
                                0x800000000000808aULL,
                                0x8000000080008000ULL,
                                0x808bULL,
                                0x80000001ULL,
                                0x8000000080008081ULL,
                                0x8000000000008009ULL,
                                0x8aULL,
                                0x88ULL,
                                0x80008009ULL,
                                0x8000000aULL,
                                0x8000808bULL,
                                0x800000000000008bULL,
                                0x8000000000008089ULL,
                                0x8000000000008003ULL,
                                0x8000000000008002ULL,
                                0x8000000000000080ULL,
                                0x800aULL,
                                0x800000008000000aULL,
                                0x8000000080008081ULL,
                                0x8000000000008080ULL,
                                0x80000001ULL,
                                0x8000000080008008ULL};

/*** Helper macros to unroll the permutation. ***/
#define rol(x, s) (((x) << s) | ((x) >> (64 - s)))
#define REPEAT6(e) e e e e e e
#define REPEAT24(e) REPEAT6(e e e e)
#define REPEAT5(e) e e e e e
#define FOR5(v, s, e)                                                          \
  v = 0;                                                                       \
  REPEAT5(e; v += s;)
// Declarations
void copy_sharing(size_t d, uint32_t *dst, size_t dst_stride,
                  const uint32_t *src, size_t src_stride);
void masked_and(size_t d, uint32_t *out, size_t out_stride,
                const uint32_t *a, size_t a_stride,
                const uint32_t *b, size_t b_stride);
void masked_xor(size_t d, uint32_t *out, size_t out_stride,
                const uint32_t *a, size_t a_stride,
                const uint32_t *b, size_t b_stride);
uint32_t random_uint32(void);
void masked_random_uniform16(uint16_t *output, size_t len);
uint16_t ct_less_than(uint16_t a, uint16_t b);


void masked_keccak(MaskedKeccakState *state) {
  uint8_t x, y;
  for (int i = 0; i < NROUNDS; i++) {
    // Sharewise implementation for Theta, Rho and phi
    for (int j = 0; j < MASKING_N; j++) {
      uint64_t *a = &state->w[j][0];
      uint64_t b[5];
      uint64_t t = 0;
      // Theta
      FOR5(x, 1, b[x] = 0; FOR5(y, 5, b[x] ^= a[x + y];))
      FOR5(x, 1,
           FOR5(y, 5, a[y + x] ^= b[(x + 4) % 5] ^ ROL(b[(x + 1) % 5], 1);))
      // Rho and pi
      t = a[1];
      x = 0;
      REPEAT24(b[0] = a[pi[x]]; a[pi[x]] = ROL(t, rho[x]); t = b[0]; x++;)
    }
    // Chi: non-linear -> not sharewise.
    // Masked gadgets are implemented on 32-bit words and Chi does not contain
    // rotations, so we can work on 32-bit words
    for (y = 0; y < 25; y += 5) {
      for (int off = 0; off < 2; off++) {
        uint32_t sb_state[5 * MASKING_N];
        size_t sb_state_msk_stride = 1;        // in 32-bit words
        size_t sb_state_data_stride = MASKING_N; // in 32-bit words
        uint32_t *sb_in = &state->h[0][2 * y + off];
        size_t sb_in_data_stride = 2;     // in 32-bit words
        size_t sb_in_msk_stride = 2 * 25; // in 32-bit words

        for (x = 0; x < 5; x++) {
          copy_sharing(
              MASKING_N, sb_state + x * sb_state_data_stride, sb_state_msk_stride,
              sb_in + ((x + 1) % 5) * sb_in_data_stride, sb_in_msk_stride);
          sb_state[x * sb_state_data_stride] =
              ~sb_state[x * sb_state_data_stride]; // NOT: on a single share
          masked_and(
              MASKING_N, sb_state + x * sb_state_data_stride, sb_state_msk_stride,
              sb_state + x * sb_state_data_stride, sb_state_msk_stride,
              sb_in + ((x + 2) % 5) * sb_in_data_stride, sb_in_msk_stride);
        }
        for (x = 0; x < 5; x++) {
          masked_xor(MASKING_N, sb_in + x * sb_in_data_stride, sb_in_msk_stride,
                     sb_in + x * sb_in_data_stride, sb_in_msk_stride,
                     sb_state + x * sb_state_data_stride, sb_state_msk_stride);
        }
      }
    }
    // Iota
    // Add constant: on a single share
    state->w[0][0] ^= RC[i];
  }
}

#define XORU64(value, address, byte)                                           \
  do {                                                                         \
    (value)[(address) >> 3] ^= (((uint64_t)(byte)) << 8 * ((address)&0x7));    \
  } while (0)
#define ExtractU64(value, address)                                             \
  (((value)[(address) >> 3] >> 8 * ((address)&0x7)) & 0xFF)


#define PRINT_STATE_LANES(label, state)                                \
    do {                                                               \
        printf("\n=== %s ===\n", label);                               \
        for (int j = 0; j < MASKING_N; j++) {                          \
            printf(" Share %d:\n", j);                                 \
            for (int i = 0; i < 25; i++) {                             \
                printf("  w[%2d][%2d] = 0x%016" PRIx64 "\n", j, i,     \
                       (state)->w[j][i]);                              \
            }                                                          \
        }                                                              \
    } while (0)

#define PRINT_OUTPUT(label, outbuf, outlen, out_data_stride)           \
    do {                                                               \
        printf("\n=== %s ===\n", label);                               \
        for (size_t i = 0; i < outlen; i++) {                          \
            printf("%02x ", outbuf[i * out_data_stride]);             \
            if ((i + 1) % 16 == 0) printf("\n");                       \
        }                                                              \
        printf("\n");                                                  \
    } while (0)

void masked_hash_keccak(uint8_t *out, size_t outlen, size_t out_msk_stride,
                        size_t out_data_stride, const uint8_t *in, size_t inlen,
                        size_t in_msk_stride, size_t in_data_stride,
                        size_t rate, uint8_t delim) {
  MaskedKeccakState state;
  memset(&state.w[0][0], 0, sizeof(state));
  uint64_t *msk_a = &state.w[0][0];

  PRINT_STATE_LANES("Initial zeroed state", &state);

  // Absorb input.
  while (inlen >= rate) {
    for (size_t i = 0; i < rate; i++) {
      for (size_t j = 0; j < MASKING_N; j++) {
        XORU64(msk_a, i + j * Plen, in[j * in_msk_stride + i * in_data_stride]);
      }
    }
    PRINT_STATE_LANES("After absorbing full input block", &state);
    masked_keccak(&state);
    PRINT_STATE_LANES("After Keccak on full input block", &state);
    in += rate * in_data_stride;
    inlen -= rate;
  }

  // Absorb last block if any
  for (size_t i = 0; i < inlen; i++) {
    for (size_t j = 0; j < MASKING_N; j++) {
      XORU64(msk_a, i + j * Plen, in[j * in_msk_stride + i * in_data_stride]);
    }
  }
  PRINT_STATE_LANES("After absorbing partial input block", &state);

  // Xor in the DS and pad frame.
  XORU64(msk_a, inlen, delim);
  XORU64(msk_a, rate - 1, 0x80);
  PRINT_STATE_LANES("After adding delim and padding", &state);

  // Apply P
  masked_keccak(&state);
  PRINT_STATE_LANES("After final Keccak before squeezing", &state);

  // Squeeze output.
  while (outlen >= rate) {
    for (size_t i = 0; i < rate; i++) {
      for (size_t j = 0; j < MASKING_N; j++) {
        out[i * out_data_stride + j * out_msk_stride] =
            ExtractU64(msk_a, i + j * Plen);
      }
    }
    masked_keccak(&state);
    out += rate * out_data_stride;
    outlen -= rate;
  }

  for (size_t i = 0; i < outlen; i++) {
    for (size_t j = 0; j < MASKING_N; j++) {
      out[i * out_data_stride + j * out_msk_stride] =
          ExtractU64(msk_a, i + j * Plen);
    }
  }

  PRINT_OUTPUT("Extracted Output Share 0", out, outlen, out_data_stride);
}


void masked_shake256(uint8_t *output, size_t outlen,
                     size_t out_msk_stride, size_t out_data_stride,
                     const uint8_t *input, size_t inlen,
                     size_t in_msk_stride, size_t in_data_stride) {
  // SHAKE256 parameters:
  // rate = 136 bytes (1088 bits), domain separation byte = 0x1F

  const uint8_t SHAKE256_DOMAIN_SEP = 0x1F;

  masked_hash_keccak(output, outlen,
                     out_msk_stride, out_data_stride,
                     input, inlen,
                     in_msk_stride, in_data_stride,
                     SHAKE256_RATE, SHAKE256_DOMAIN_SEP);
}



// Output length is fixed
#define TARGET_COEFFS 256
#define MAX_ATTEMPTS 512

int rej_uniform_constant_time(int16_t *out) {
    uint16_t buf[MAX_ATTEMPTS];
    masked_random_uniform16(buf, MAX_ATTEMPTS);  // Use CSRNG

    unsigned int count = 0;

    for (int i = 0; i < MAX_ATTEMPTS; i++) {
        uint16_t val = buf[i];

        // Constant-time mask: val < KYBER_Q
        uint16_t keep = ct_less_than(val, KYBER_Q);  // returns 0xFFFF or 0x0000

        out[count] = (val & keep) | (out[count] & ~keep);
        count += (keep & 1);

        if (count == TARGET_COEFFS) break;
    }

    return count == TARGET_COEFFS ? 0 : -1;
}

// Rejection sampling: fills `r` with uniform integers < KYBER_Q from `buf`
// Returns the number of coefficients written into `r`
//NOT SECURE MUST NOT BE USED FOR MASKED VALUES
unsigned int rej_uniform(int16_t *r,
                         unsigned int len,
                         const uint8_t *buf,
                         unsigned int buflen)
{
    unsigned int ctr = 0, pos = 0;
    uint16_t val;

    while (ctr < len && pos + 3 <= buflen) {
        val = buf[pos] | ((uint16_t)buf[pos + 1] << 8);
        pos += 2;

        if (val < 19 * KYBER_Q) {
            r[ctr++] = val % KYBER_Q;
        }
    }

    return ctr;
}

void copy_sharing(size_t d,
                  uint32_t *dst, size_t dst_stride,
                  const uint32_t *src, size_t src_stride) {
  for (size_t i = 0; i < d; i++) {
    dst[i * dst_stride] = src[i * src_stride];
  }
}

void masked_and(size_t d,
                uint32_t *out, size_t out_stride,
                const uint32_t *a, size_t a_stride,
                const uint32_t *b, size_t b_stride) {
  for (size_t i = 0; i < d; i++) {
    for (size_t j = 0; j < d; j++) {
      uint32_t x = a[i * a_stride] & b[j * b_stride];
      if (i == j) {
        out[i * out_stride] = x;
      } else if (i < j) {
        uint32_t r = random_uint32();  // Secure random per pair
        out[i * out_stride] ^= r;
        out[j * out_stride] ^= x ^ r;
      }
    }
  }
}


void masked_xor(size_t d,
                uint32_t *out, size_t out_stride,
                const uint32_t *a, size_t a_stride,
                const uint32_t *b, size_t b_stride) {
  for (size_t i = 0; i < d; i++) {
    out[i * out_stride] = a[i * a_stride] ^ b[i * b_stride];
  }
}

uint32_t random_uint32(void) {
    uint32_t value;
    while (HAL_RNG_GenerateRandomNumber(&hrng, &value) != HAL_OK) {
        // Optionally: insert timeout or fail-safe to avoid infinite loop
    }
    return value;
}

void masked_sha3_512(uint8_t *output, size_t out_msk_stride,
                     size_t out_data_stride, const uint8_t *input, size_t inlen,
                     size_t in_msk_stride, size_t in_data_stride) {
  masked_hash_keccak(output, 64, out_msk_stride, out_data_stride, input, inlen,
                     in_msk_stride, in_data_stride, 72, 0x06);
}

void masked_sha3_256(masked_u8_32 *output,
                     const uint8_t *input,
                     size_t inlen,
                     size_t in_msk_stride,
                     size_t in_data_stride) {
  masked_hash_keccak(
      (uint8_t *) &output->bytes[0].share[0],  // reinterpret as [share][byte]
      32,                                      // outlen
      1, MASKING_ORDER,                        // out strides: [share][byte]
      input, inlen,
      in_msk_stride, in_data_stride,
      136, 0x06);                              // SHA3-256 rate + delimiter
}



