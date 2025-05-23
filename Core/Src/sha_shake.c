#include "sha_shake.h"
#include "masked_keccak.h"
#include <string.h>
#include "params.h"

// === Public API Implementations ===
void masked_keccak_sponge(uint8_t *output, size_t output_len,
                          const uint8_t *input, size_t input_len,
                          size_t rate, uint8_t domain_sep) {
    masked_uint64_t state[5][5];

    //Step 1: Initialize state
    for (int x = 0; x < 5; x++) {
        for (int y = 0; y < 5; y++) {
            for (int i = 0; i < MASKING_N; i++) {
                state[x][y].share[i] = 0;
            }
        }
    }

    //Step 2: Absorb full input blocks
    size_t offset = 0;
    while (input_len >= rate) {
        for (int i = 0; i < rate; i += 8) {
            uint64_t lane = 0;
            for (int j = 0; j < 8; j++) {
                lane |= ((uint64_t)input[offset + i + j]) << (8 * j);
            }

            size_t x = (i / 8) % 5;
            size_t y = (i / 8) / 5;

            masked_uint64_t masked_lane;
            masked_value_set(&masked_lane, lane);
            masked_xor(&state[x][y], &state[x][y], &masked_lane);
        }

        masked_keccak_f1600(state);
        offset += rate;
        input_len -= rate;
    }

    //Step 3: Final padded block with domain separation
    uint8_t block[rate];
    for (size_t i = 0; i < rate; ++i) {
        block[i] = 0;
    }

    for (size_t i = 0; i < input_len; ++i) {
        block[i] = input[offset + i];
    }

    block[input_len] ^= domain_sep;   // Domain separation marker (e.g., 0x06 or 0x1F)
    block[rate - 1] ^= 0x80;          // Padding rule per Keccak spec

    for (int i = 0; i < rate; i += 8) {
        uint64_t lane = 0;
        for (int j = 0; j < 8 && (i + j) < rate; j++) {
            lane |= ((uint64_t)block[i + j]) << (8 * j);
        }

        size_t x = (i / 8) % 5;
        size_t y = (i / 8) / 5;

        masked_uint64_t masked_lane;
        masked_value_set(&masked_lane, lane);
        masked_xor(&state[x][y], &state[x][y], &masked_lane);
    }

    masked_keccak_f1600(state);

    //Step 4: Squeeze the requested output
    masked_squeeze(output, output_len, state, rate);
}


// SHA3-224: 28-byte output, 1152-bit rate
void masked_sha3_224(uint8_t *output, const uint8_t *input, size_t input_len) {
    masked_keccak_sponge(output, 28, input, input_len, 1152 / 8, DOMAIN_SHA3);
}

// SHA3-256: Output = 32 bytes, Rate = 136 bytes (1088 bits)
void masked_sha3_256(uint8_t *output, const uint8_t *input, size_t input_len) {
    masked_keccak_sponge(output, 32, input, input_len, 136, DOMAIN_SHA3);
}

void masked_sha3_256_remain_masked(masked_u8_32 *output, const uint8_t *input, size_t input_len) {
    masked_keccak_state ctx;
    ctx.rate = 136;  // SHA3-256 bitrate

    masked_shake128_absorb_once(&ctx, input, input_len);

    uint8_t tmp[32];
    masked_shake128_squeezeblocks(tmp, 1, &ctx);  // squeeze 32 bytes (1 block is enough)

    for (size_t i = 0; i < 32; ++i) {
        uint8_t val = tmp[i];
        uint8_t acc = val;

        for (int j = 0; j < MASKING_N - 1; ++j) {
            output->bytes[i].share[j] = get_random8();  // secure per-byte randomness
            acc ^= output->bytes[i].share[j];
        }

        output->bytes[i].share[MASKING_N - 1] = acc;
    }
}


// SHA3-384: 48-byte output, 832-bit rate
void masked_sha3_384(uint8_t *output, const uint8_t *input, size_t input_len) {
    masked_keccak_sponge(output, 48, input, input_len, 832 / 8, DOMAIN_SHA3);
}

// SHA3-512: Output = 64 bytes, Rate = 72 bytes (576 bits)
void masked_sha3_512(uint8_t *output, const uint8_t *input, size_t input_len) {
    masked_keccak_sponge(output, 64, input, input_len, 72, DOMAIN_SHA3);
}

// SHAKE128: Extendable output, Rate = 168 bytes (1344 bits)
void masked_shake128(uint8_t *output, size_t output_len, const uint8_t *input, size_t input_len) {
    masked_keccak_sponge(output, output_len, input, input_len, 168, DOMAIN_SHAKE);
}

// SHAKE256: Extendable output, Rate = 136 bytes (1088 bits)
void masked_shake256(uint8_t *output, size_t output_len, const uint8_t *input, size_t input_len) {
    masked_keccak_sponge(output, output_len, input, input_len, 136, DOMAIN_SHAKE);
}

// Kyber Wrappers
void masked_shake128_absorb_once(keccak_state *state, const uint8_t *input, size_t inlen) {
    unmasked_absorb(state, input, inlen, SHAKE128_RATE);
}

void masked_shake256_absorb_once(masked_uint64_t state[5][5], const uint8_t *input, size_t inlen) {
    masked_absorb(state, input, inlen, SHAKE256_RATE);
}

// Optional masked sponge interface
void masked_shake128_sponge(uint8_t *output, size_t outlen, const uint8_t *input, size_t inlen) {
    masked_keccak_sponge(output, outlen, input, inlen, SHAKE128_RATE, DOMAIN_SHAKE);
}

void masked_shake256_sponge(uint8_t *output, size_t outlen, const uint8_t *input, size_t inlen) {
    masked_keccak_sponge(output, outlen, input, inlen, SHAKE256_RATE, DOMAIN_SHAKE);
}

/// ~~~ARITHMETIC IMPLEMENTATIONS ~~~

void masked_keccak_sponge_arithmetic(uint8_t *output, size_t output_len,
                                     const uint8_t *input, size_t input_len,
                                     size_t rate, uint8_t domain_sep) {
    masked_uint64_t state[5][5];

    for (int x = 0; x < 5; x++) {
        for (int y = 0; y < 5; y++) {
            for (int i = 0; i < MASKING_N; i++) {
                state[x][y].share[i] = 0;
            }
        }
    }

    size_t offset = 0;
    while (input_len >= rate) {
        for (int i = 0; i < rate; i += 8) {
            uint64_t lane = 0;
            for (int j = 0; j < 8; j++) {
                lane |= ((uint64_t)input[offset + i + j]) << (8 * j);
            }

            size_t x = (i / 8) % 5;
            size_t y = (i / 8) / 5;

            masked_uint64_t masked_lane;
            masked_value_set_arithmetic(&masked_lane, lane);
            masked_add_arithmetic(&state[x][y], &state[x][y], &masked_lane);
        }

        masked_keccak_f1600_arithmetic(state);
        offset += rate;
        input_len -= rate;
    }

    uint8_t block[rate];
    memset(block, 0, rate);
    memcpy(block, input + offset, input_len);

    block[input_len] ^= domain_sep;
    block[rate - 1] ^= 0x80;

    for (int i = 0; i < rate; i += 8) {
        uint64_t lane = 0;
        for (int j = 0; j < 8 && (i + j) < rate; j++) {
            lane |= ((uint64_t)block[i + j]) << (8 * j);
        }

        size_t x = (i / 8) % 5;
        size_t y = (i / 8) / 5;

        masked_uint64_t masked_lane;
        masked_value_set_arithmetic(&masked_lane, lane);
        masked_add_arithmetic(&state[x][y], &state[x][y], &masked_lane);
    }

    masked_keccak_f1600_arithmetic(state);
    masked_squeeze_arithmetic(output, output_len, state, rate);
}

void masked_sha3_256_remain_masked_arithmetic(masked_u8_32 *output, const uint8_t *input, size_t input_len) {
    masked_keccak_state ctx;
    ctx.rate = 136;  // SHA3-256 bitrate

    masked_shake128_absorb_once_arithmetic(&ctx, input, input_len);

    // Squeeze one full 32-byte block
    uint8_t tmp[32];
    masked_shake128_squeezeblocks_arithmetic(tmp, 1, ctx.state, ctx.rate);

    // Mask each byte additively
    for (size_t i = 0; i < 32; ++i) {
        uint8_t val = tmp[i];
        uint8_t acc = val;

        for (int j = 0; j < MASKING_N - 1; ++j) {
            output->bytes[i].share[j] = get_random8();  // Independent randomness
            acc -= output->bytes[i].share[j];
        }

        output->bytes[i].share[MASKING_N - 1] = acc;
    }
}


void masked_sha3_224_arithmetic(uint8_t *output, const uint8_t *input, size_t input_len) {
    masked_keccak_sponge_arithmetic(output, 28, input, input_len, 1152 / 8, DOMAIN_SHA3);
}

void masked_sha3_256_arithmetic(uint8_t *output, const uint8_t *input, size_t input_len) {
    masked_keccak_sponge_arithmetic(output, 32, input, input_len, 136, DOMAIN_SHA3);
}

void masked_sha3_384_arithmetic(uint8_t *output, const uint8_t *input, size_t input_len) {
    masked_keccak_sponge_arithmetic(output, 48, input, input_len, 832 / 8, DOMAIN_SHA3);
}

void masked_sha3_512_arithmetic(uint8_t *output, const uint8_t *input, size_t input_len) {
    masked_keccak_sponge_arithmetic(output, 64, input, input_len, 72, DOMAIN_SHA3);
}

void masked_shake128_arithmetic(uint8_t *output, size_t output_len, const uint8_t *input, size_t input_len) {
    masked_keccak_sponge_arithmetic(output, output_len, input, input_len, 168, DOMAIN_SHAKE);
}

void masked_shake256_arithmetic(uint8_t *output, size_t output_len, const uint8_t *input, size_t input_len) {
    masked_keccak_sponge_arithmetic(output, output_len, input, input_len, 136, DOMAIN_SHAKE);
}

void masked_shake128_absorb_once_arithmetic(masked_keccak_state *ctx, const uint8_t *input, size_t input_len) {
    ctx->rate = 168;
    masked_absorb_arithmetic(ctx->state, input, input_len, ctx->rate);
}

void masked_shake256_absorb_once_arithmetic(masked_keccak_state *ctx, const uint8_t *input, size_t input_len) {
    ctx->rate = 136;
    masked_absorb_arithmetic(ctx->state, input, input_len, ctx->rate);
}

void masked_shake128_sponge_arithmetic(uint8_t *output, size_t outlen, const uint8_t *input, size_t inlen) {
    masked_keccak_sponge_arithmetic(output, outlen, input, inlen, SHAKE128_RATE, DOMAIN_SHAKE);
}

void masked_shake256_sponge_arithmetic(uint8_t *output, size_t outlen, const uint8_t *input, size_t inlen) {
    masked_keccak_sponge_arithmetic(output, outlen, input, inlen, SHAKE256_RATE, DOMAIN_SHAKE);
}

