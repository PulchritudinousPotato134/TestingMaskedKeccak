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
#define Plen 200

#define rol(x, s) (((x) << s) | ((x) >> (64 - s)))
#define REPEAT6(e) e e e e e e
#define REPEAT24(e) REPEAT6(e e e e)
#define REPEAT5(e) e e e e e
#define FOR5(v, s, e)                                                          \
  v = 0;                                                                       \
  REPEAT5(e; v += s;)

/********** Declarations (functions and macros that need fixing) **********/
void copy_sharing(size_t d, uint32_t *dst, size_t dst_stride,
                  const uint32_t *src, size_t src_stride);
void masked_and(size_t d,
                uint32_t *out, size_t out_stride,
                const uint32_t *a, size_t a_stride,
                const uint32_t *b, size_t b_stride);
void masked_xor(size_t d,
                uint32_t *out, size_t out_stride,
                const uint32_t *a, size_t a_stride,
                const uint32_t *b, size_t b_stride);
uint32_t random_uint32(void);
void masked_random_uniform16(uint16_t *output, size_t len);
uint16_t ct_less_than(uint16_t a, uint16_t b);




void masked_keccak(MaskedKeccakState *state) {
  uint8_t x, y;

  for (int i = 0; i < NROUNDS; i++) {
    printf("\n>>> Round %d <<<\n", i);

    // Sharewise Theta, Rho, Pi
    for (int j = 0; j < MASKING_N; j++) {
      uint64_t *a = &state->w[j][0];
      uint64_t b[5];

      // Theta step: Apply to all shares
      for (int x = 0; x < 5; x++) {
          b[x] = 0;
          for (int y = 0; y < 5; y++) {
              b[x] ^= a[x + y];  // XOR over shares
          }
      }

      for (int x = 0; x < 5; x++) {
          for (int y = 0; y < 5; y++) {
              a[x + y] ^= b[(x + 4) % 5] ^ ROL(b[(x + 1) % 5], 1); // Apply rotations
          }
      }

      // Rho and Pi steps
      uint64_t t = a[1]; // Temporary value for shifting

      for (int x = 0; x < 24; x++) {
          a[pi[x]] = ROL(t, rho[x]);
          t = a[pi[x]];
      }
    }

    // Debug state after Theta/Rho/Pi
    for (int j = 0; j < MASKING_N; j++) {
      printf("Share %d state after linear steps:\n", j);
      for (int k = 0; k < 25; k++) {
        printf("  w[%d][%2d] = 0x%016llx\n", j, k, state->w[j][k]);
      }
    }

    // Chi step (non-linear)
    for (int j = 0; j < MASKING_N; j++) {
        for (int y = 0; y < 25; y += 5) {
            for (int off = 0; off < 2; off++) {
                uint32_t sb_state[5 * MASKING_N]; // Store shared state values

                // Perform Chi step across all shares
                for (int x = 0; x < 5; x++) {
                    masked_and(MASKING_N, sb_state + x * MASKING_N, sb_state_msk_stride,
                                state->h[0][2 * y + off] + ((x + 2) % 5) * sb_in_data_stride, sb_in_msk_stride);
                    masked_xor(MASKING_N, state->h[0][2 * y + off] + x * sb_in_data_stride, sb_in_msk_stride,
                               state->h[0][2 * y + off] + x * sb_in_data_stride, sb_in_msk_stride,
                               sb_state + x * sb_state_data_stride, sb_state_msk_stride);
                }
            }
        }
    }

    // Iota step (does not need masking)
    state->w[0][0] ^= RC[i];

  }

  // Final debug dump
  printf("\n>>> Final state after all rounds <<<\n");
  for (int j = 0; j < MASKING_N; j++) {
    printf("Final Share %d:\n", j);
    for (int k = 0; k < 25; k++) {
      printf("  w[%d][%2d] = 0x%016llx\n", j, k, state->w[j][k]);
    }
  }
}



void masked_hash_keccak(uint8_t *out, size_t outlen,
                        size_t out_msk_stride, size_t out_data_stride,
                        const uint8_t *in, size_t inlen,
                        size_t in_msk_stride, size_t in_data_stride,
                        size_t rate, uint8_t delim) {
  MaskedKeccakState state;
  memset(&state, 0, sizeof(state));
  uint64_t *msk_a = &state.w[0][0];

  // === Absorb full blocks ===
  while (inlen >= rate) {
    for (size_t i = 0; i < rate; i++) {
      for (size_t j = 0; j < MASKING_N; j++) {
    	  uint8_t byte = in[i * in_msk_stride + j * in_data_stride];
        XORU64(&state.w[j][0], i, byte);
      }
    }
    masked_keccak(&state);
    in += rate * in_msk_stride;
    inlen -= rate;
  }

  // === Absorb final partial block — FIXED ===
  for (size_t i = 0; i < inlen; i++) {
      size_t lane_idx = i / 8;
      size_t byte_offset = i % 8;
      for (size_t j = 0; j < MASKING_N; j++) {
          uint8_t byte = in[j * in_msk_stride + i * in_data_stride];
          state.w[j][lane_idx] ^= ((uint64_t)byte) << (8 * byte_offset);
      }
  }

  // === Domain separation and padding — FIXED ===
  size_t ds_lane = inlen / 8;
  size_t ds_offset = inlen % 8;

  for (int j = 0; j < MASKING_N; j++) {
      uint8_t delim_byte = (j == 0) ? delim : 0x00;
      uint8_t pad_byte = (j == 0) ? 0x80 : 0x00;

      state.w[j][ds_lane] ^= ((uint64_t)delim_byte) << (8 * ds_offset);
      state.w[j][(rate - 1) / 8] ^= ((uint64_t)pad_byte) << (8 * ((rate - 1) % 8));
  }

  // === Keccak permutation ===
  masked_keccak(&state);

  // === Squeeze full output blocks ===
  while (outlen >= rate) {
    for (size_t i = 0; i < rate; i++) {
      size_t lane_idx = i / 8;
      size_t byte_offset = i % 8;
      for (size_t j = 0; j < MASKING_N; j++) {
        uint64_t lane = state.w[j][lane_idx];
        out[i * out_data_stride + j * out_msk_stride] =
            (lane >> (8 * byte_offset)) & 0xFF;
      }
    }
    masked_keccak(&state);
    out += rate * out_data_stride;
    outlen -= rate;
  }

  // === Squeeze final partial block ===
  for (size_t i = 0; i < outlen; i++) {
    size_t lane_idx = i / 8;
    size_t byte_offset = i % 8;
    for (size_t j = 0; j < MASKING_N; j++) {
      uint64_t lane = state.w[j][lane_idx];
      out[i * out_data_stride + j * out_msk_stride] =
          (lane >> (8 * byte_offset)) & 0xFF;
    }
  }
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
        out[i * out_stride] ^= r;     // XOR random value to ensure security
        out[j * out_stride] ^= x ^ r; // XOR random and computed value
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

