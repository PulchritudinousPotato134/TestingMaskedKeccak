
#include <string.h>
#include <stddef.h>
#include "masked_types.h"
#include "masked_keccak_f1600.h"
#include "masked_absorb.h"
#include "masked_squeeze.h"

#define SHA3_512_RATE 72             // SHA3-512 rate in bytes
#define SHA3_512_OUTPUT_SIZE 64      // SHA3-512 output in bytes

void masked_sha3_512(uint8_t *output, const uint8_t *input, size_t input_len) {
    masked_uint64_t state[5][5];

    // === Zero the state ===
    for (int x = 0; x < 5; x++) {
        for (int y = 0; y < 5; y++) {
            for (int i = 0; i < MASKING_N; i++) {
                state[x][y].share[i] = 0;
            }
        }
    }

    // === Absorb input using masked absorb ===
    printf("Starting masked_absorb\n");
    masked_absorb(state, input, input_len);
    printf("Finished absorb\n");

    // === Squeeze output using masked squeeze ===
    masked_squeeze(output, SHA3_512_OUTPUT_SIZE, state);
}


/*
void masked_sha3_512(uint8_t *output, const uint8_t *input, size_t input_len) {
    masked_uint64_t state[5][5];

    // === Zero the state ===
    for (int x = 0; x < 5; x++) {
        for (int y = 0; y < 5; y++) {
            for (int i = 0; i < MASKING_N; i++) {
                state[x][y].share[i] = 0;
            }
        }
    }

    // === Absorb input in SHA3-512 blocks (rate = 72 bytes) ===
    size_t offset = 0;
    while (input_len >= SHA3_512_RATE) {
        for (int i = 0; i < SHA3_512_RATE; i++) {
            size_t x = (i / 8) % 5;
            size_t y = (i / 8) / 5;
            size_t byte_pos = i % 8;
            uint8_t *s = (uint8_t *)&state[x][y].share[0];
            s[byte_pos] ^= input[offset + i];
        }

        masked_keccak_f1600(state);
        offset += SHA3_512_RATE;
        input_len -= SHA3_512_RATE;
    }

    // === Final block with SHA3 padding (0x06 + 0x80) ===
    uint8_t block[SHA3_512_RATE] = {0};
    memcpy(block, input + offset, input_len);
    block[input_len] = 0x06;               // SHA3 domain separator
    block[SHA3_512_RATE - 1] |= 0x80;      // Multi-rate pad bit

    for (int i = 0; i < SHA3_512_RATE; i++) {
        size_t x = (i / 8) % 5;
        size_t y = (i / 8) / 5;
        size_t byte_pos = i % 8;
        uint8_t *s = (uint8_t *)&state[x][y].share[0];
        s[byte_pos] ^= block[i];
    }

    masked_keccak_f1600(state);

    // === Squeeze out final 64 bytes ===
    size_t output_offset = 0;
    while (output_offset < SHA3_512_OUTPUT_SIZE) {
        for (int i = 0; i < SHA3_512_RATE && output_offset < SHA3_512_OUTPUT_SIZE; i++) {
            size_t x = (i / 8) % 5;
            size_t y = (i / 8) / 5;
            size_t byte_pos = i % 8;

            uint64_t lane = 0;
            for (int j = 0; j < MASKING_N; j++) {
                lane ^= state[x][y].share[j];
            }

            output[output_offset++] = (lane >> (8 * byte_pos)) & 0xFF;
        }

        if (output_offset < SHA3_512_OUTPUT_SIZE) {
            masked_keccak_f1600(state);
        }
    }
}
*/
